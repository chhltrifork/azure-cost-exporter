#!/usr/bin/python
# -*- coding:utf-8 -*-
# Filename: main.py

import argparse
import logging
import os
import sys
import time
from datetime import datetime, timezone

import yaml
from azure.core.exceptions import HttpResponseError
from azure.identity import ClientSecretCredential
from azure.mgmt.costmanagement import CostManagementClient
from azure.mgmt.costmanagement.models import QueryDefinition, QueryTimePeriod
from dateutil.relativedelta import relativedelta
from envyaml import EnvYAML
from prometheus_client import Gauge
from prometheus_client import start_http_server


# noinspection PyTypeChecker
class MetricExporter:
    def __init__(self, polling_interval_seconds, metric_name, metric_name_usd, group_by, targets, secrets):
        self.polling_interval_seconds = polling_interval_seconds
        self.metric_name = metric_name
        self.metric_name_usd = metric_name_usd
        self.group_by = group_by
        self.targets = targets
        self.secrets = secrets
        # we have verified that there is at least one target
        self.labels = set(targets[0].keys())
        # for now we only support exporting one type of cost (ActualCost)
        self.labels.add("ChargeType")
        self.labels.add("Currency")
        if group_by["enabled"]:
            for group in group_by["groups"]:
                self.labels.add(group["label_name"])
        self.azure_daily_cost = Gauge(self.metric_name, "Daily cost of an Azure account in billing currency",
                                      self.labels)
        self.azure_daily_cost_usd = Gauge(self.metric_name_usd, "Daily cost of an Azure account in USD", self.labels)

    def run_metrics_loop(self):
        while True:
            # every time we clear up all the existing labels before setting new ones
            self.azure_daily_cost.clear()
            self.azure_daily_cost_usd.clear()

            self.fetch()
            time.sleep(self.polling_interval_seconds)

    def init_azure_client(self, tenant_id):
        client = CostManagementClient(
            credential=ClientSecretCredential(
                tenant_id=tenant_id,
                client_id=self.secrets[tenant_id]["client_id"],
                client_secret=self.secrets[tenant_id]["client_secret"],
            )
        )

        return client

    def query_azure_cost_explorer(self, azure_client, subscription, group_by, start_date, end_date, tenant_id):
        scope = f"/subscriptions/{subscription}"

        groups = list()
        if group_by["enabled"]:
            for group in group_by["groups"]:
                groups.append({"type": group["type"], "name": group["name"]})

        # Get config from tenant setup
        groupings_tenant = dict()
        for target in self.targets:
            if tenant_id is target["TenantId"]:
                groupings_tenant = target["AdditionalGroupBy"]
                if groupings_tenant == 'ResourceGroup':
                    print("Adding ResourceGroup to groupings")
                    groups.append({"type": "Dimension", "name": "ResourceGroup"})
                else:
                    None
                break

        query = QueryDefinition(
            type="ActualCost",
            dataset={
                "granularity": "Daily",
                "aggregation": {
                    "totalCost": {"name": "Cost", "function": "Sum"},
                    "totalCostUSD": {"name": "CostUSD", "function": "Sum"}
                },
                "grouping": groups,
            },
            timeframe="Custom",
            time_period=QueryTimePeriod(
                from_property=datetime(start_date.year, start_date.month, start_date.day, tzinfo=timezone.utc),
                to=datetime(end_date.year, end_date.month, end_date.day, tzinfo=timezone.utc),
            ),
        )
        result = azure_client.query.usage(scope, query)
        return result.as_dict()

    def expose_metrics(self, azure_account, result):
        cost = float(result[0])
        costUsd = float(result[1])

        if not self.group_by["enabled"]:
            self.azure_daily_cost.labels(**azure_account, ChargeType="ActualCost", Currency=result[3]).set(cost)
            self.azure_daily_cost_usd.labels(**azure_account, ChargeType="ActualCost", Currency="USD").set(costUsd)
        else:
            merged_minor_cost = 0
            merged_minor_cost_usd = 0
            group_key_values = dict()
            for i in range(len(self.group_by["groups"])):
                value = result[i + 3]
                group_key_values.update({self.group_by["groups"][i]["label_name"]: value})

            if self.group_by["merge_minor_cost"]["enabled"] and cost < self.group_by["merge_minor_cost"]["threshold"]:
                merged_minor_cost += cost
                merged_minor_cost_usd += costUsd
            else:
                self.azure_daily_cost.labels(**azure_account, **group_key_values, ChargeType="ActualCost",
                                             Currency=result[len(self.group_by["groups"]) + 3]).set(cost)
                self.azure_daily_cost_usd.labels(**azure_account, **group_key_values, ChargeType="ActualCost",
                                                 Currency="USD").set(costUsd)

            if merged_minor_cost > 0:
                group_key_values = dict()
                for i in range(len(self.group_by["groups"])):
                    group_key_values.update(
                        {self.group_by["groups"][i]["label_name"]: self.group_by["merge_minor_cost"]["tag_value"]}
                    )
                self.azure_daily_cost.labels(**azure_account, **group_key_values, ChargeType="ActualCost").set(
                    merged_minor_cost
                )
                self.azure_daily_cost_usd.labels(**azure_account, **group_key_values, ChargeType="ActualCost").set(
                    merged_minor_cost_usd
                )

    def fetch(self):
        for azure_account in self.targets:
            print("[%s] Querying cost data for Azure tenant %s" % (datetime.now(), azure_account["TenantId"]))
            azure_client = self.init_azure_client(azure_account["TenantId"])

            try:
                end_date = datetime.today()
                start_date = end_date - relativedelta(days=1)
                cost_response = self.query_azure_cost_explorer(
                    azure_client, azure_account["Subscription"], self.group_by, start_date, end_date,
                    azure_account["TenantId"]
                )
            except HttpResponseError as e:
                logging.error(e.reason)
                continue

            for result in cost_response["rows"]:
                if result[2] != int(start_date.strftime("%Y%m%d")):
                    # it is possible that Azure returns cost data which is different than the specified date
                    # for example, the query time period is 2023-07-10 00:00:00+00:00 to 2023-07-11 00:00:00+00:00
                    # Azure still returns some records for date 2023-07-11
                    continue
                else:
                    self.expose_metrics(azure_account, result)


class key_value_arg(argparse.Action):
    def __call__(self, parser, namespace,
                 values, option_string=None):
        setattr(namespace, self.dest, dict())

        for kvpair in values:
            assert len(kvpair.split("=")) == 2

            key, value = kvpair.split("=")
            getattr(namespace, self.dest)[key] = value


def generate_secret_yaml(file_path, config):
    needed_secrets = dict()
    for target in config["target_azure_accounts"]:
        needed_secrets[target["TenantId"]] = {
            "client_id": "PUT_CLIENT_ID_HERE", "client_secret": "PUT_CLIENT_SECRET_HERE"}

    with open(file_path, "w") as secret_yaml:
        yaml.dump(needed_secrets, secret_yaml)


def get_configs():
    parser = argparse.ArgumentParser(
        description="Azure Cost Exporter, exposing Azure cost data as Prometheus metrics.")
    parser.add_argument("-c", "--config", required=True,
                        help="The config file (exporter_config.yaml) for the exporter")
    parser.add_argument("-s", "--secret", default="./secret.yaml",
                        help="The secrets file (secret.yaml) that contains the credentials for each target account")
    args = parser.parse_args()

    if (not os.path.exists(args.config) or not os.path.isfile(args.config)):
        logging.error(
            "Azure Cost Exporter config file does not exist, or it is not a file!")
        sys.exit(1)

    config = EnvYAML(args.config)

    # config validation
    if len(config["target_azure_accounts"]) == 0:
        logging.error(
            "There should be at leaest one target Azure accounts defined in the config!")
        sys.exit(1)

    labels = config["target_azure_accounts"][0].keys()

    if "TenantId" not in labels or "Subscription" not in labels:
        logging.error(
            "TenantId and Subscription are mandatory keys in target_azure_accounts!")
        sys.exit(1)

    for i in range(1, len(config["target_azure_accounts"])):
        if labels != config["target_azure_accounts"][i].keys():
            logging.error(
                "All the target Azure accounts should have the same set of keys (labels)!")
            sys.exit(1)

    # read and validate secret
    if (not os.path.exists(args.secret)):
        logging.error(
            "Azure Cost Exporter secret file does not exist. secret.yaml is generated based on your config file.")
        generate_secret_yaml(args.secret, config)
        sys.exit(1)
    elif (not os.path.isfile(args.secret)):
        logging.error(
            "The specified Azure Cost Exporter secret path is not a file!")
        sys.exit(1)

    secret = EnvYAML(args.secret)

    for tenant in config["target_azure_accounts"]:
        if tenant["TenantId"] not in secret:
            logging.error("The secret for tenant %s is missing in %s!" %
                          (tenant, args.secret))
            sys.exit(1)

    return config, secret


def main(config, secrets):
    app_metrics = MetricExporter(
        polling_interval_seconds=config["polling_interval_seconds"],
        metric_name=config["metric_name"],
        metric_name_usd=config["metric_name_usd"],
        group_by=config["group_by"],
        targets=config["target_azure_accounts"],
        secrets=secrets
    )
    start_http_server(config["exporter_port"])
    app_metrics.run_metrics_loop()


if __name__ == "__main__":
    logger_format = "%(asctime)-15s %(levelname)-8s %(message)s"
    logging.basicConfig(level=logging.WARNING, format=logger_format)
    config, secrets = get_configs()
    main(config, secrets)
