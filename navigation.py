from netbox.plugins import PluginMenuItem


menu_items = (
    PluginMenuItem(
        link='plugins:plugin_juniper:firewall_list',
        link_text='Juniper Firewalls',
        permissions=['dcim.view_device'],
        buttons=()
    ),
)