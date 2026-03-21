import os
import json

def load_config(path):
    with open(path) as f:
        return json.load(f)

def merge_configs(base, override):
    result = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and key in result:
            result[key] = merge_configs(result[key], value)
        else:
            result[key] = value
    return result

class ConfigManager:
    def __init__(self, base_path, env="production"):
        self.base_path = base_path
        self.env = env
        self.config = {}

    def load(self):
        base = load_config(os.path.join(self.base_path, "base.json"))
        env_config = load_config(os.path.join(self.base_path, f"{self.env}.json"))
        self.config = merge_configs(base, env_config)
        return self.config

    def get(self, key, default=None):
        keys = key.split(".")
        value = self.config
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
            else:
                return default
        return value if value is not None else default
