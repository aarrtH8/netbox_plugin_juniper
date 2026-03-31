from netbox.plugins import PluginConfig


class PluginJuniperConfig(PluginConfig):
    name = "plugin_juniper"
    verbose_name = "Juniper NetBox"
    description = "Scan SSH d'un firewall Juniper & intégration auto dans NetBox"
    version = "1.2"
    author = "Arthur"
    base_url = "juniper"
    min_version = "4.1"


config = PluginJuniperConfig
