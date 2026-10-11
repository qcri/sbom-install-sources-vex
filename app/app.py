"""The product: a service that parses YAML documents sent by clients."""
import sys
import yaml


def handle_upload(body):
    return yaml.full_load(body)      # client data -> FullLoader (CVE-2020-14343 sink)


if __name__ == "__main__":
    for line in sys.stdin:
        print(handle_upload(line))
