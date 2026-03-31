from django.views.generic import TemplateView, View
from django.shortcuts import render, get_object_or_404, redirect
from dcim.models import Device, Interface
from ipam.models import IPAddress, VLAN, Prefix
from extras.models import Tag
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib import messages
from django.db.models import Q
from django.utils.text import slugify
from .forms import SSHForm
import paramiko
import re
import ipaddress
import logging

logger = logging.getLogger(__name__)


class FirewallListView(LoginRequiredMixin, TemplateView):
    """Vue principale avec formulaire de sélection"""
    template_name = "plugin_juniper/firewall_list.html"

    def get(self, request, *args, **kwargs):
        # Récupérer uniquement les firewalls Juniper actifs AVEC une IP configurée ET "FWL" dans le nom
        firewalls = Device.objects.filter(
            status='active'
        ).filter(
            device_type__manufacturer__name__icontains='juniper'
        ).filter(
            Q(primary_ip4__isnull=False) | Q(primary_ip6__isnull=False)
        ).filter(
            name__icontains='FWL'
        ).select_related(
            'site', 'tenant', 'device_type', 'primary_ip4', 'primary_ip6'
        ).order_by('name')
        
        return render(request, self.template_name, {
            'firewalls': firewalls,
            'form': SSHForm()
        })


class FirewallScanView(LoginRequiredMixin, View):
    """Vue de scan SSH"""

    def post(self, request, device_id):
        device = get_object_or_404(Device, pk=device_id)
        form = SSHForm(request.POST)
        interfaces = []
        security_zones = {}
        
        if not form.is_valid():
            messages.error(request, "Formulaire invalide.")
            return redirect('plugins:plugin_juniper:firewall_list')
        
        ssh_user = form.cleaned_data['ssh_user']
        ssh_pass = form.cleaned_data['ssh_pass']
        
        # Récupération de l'IP principale
        primary_ip = device.primary_ip4 or device.primary_ip6
        
        if not primary_ip:
            messages.error(request, f"Le device {device.name} n'a pas d'adresse IP principale configurée.")
            return redirect('plugins:plugin_juniper:firewall_list')
        
        # Convertir l'adresse IP en string et extraire l'IP sans le masque
        try:
            ip_str = str(primary_ip.address)
            ip = ip_str.split('/')[0] if '/' in ip_str else ip_str
        except Exception as e:
            logger.error(f"Error extracting IP from {device.name}: {e}")
            messages.error(request, f"Erreur lors de l'extraction de l'adresse IP : {str(e)}")
            return redirect('plugins:plugin_juniper:firewall_list')

        try:
            # Connexion SSH
            logger.info(f"Connexion SSH à {ip} pour {device.name}")
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(ip, username=ssh_user, password=ssh_pass, timeout=15)
            
            # Récupération des adresses IP
            logger.info(f"Récupération des adresses IP pour {device.name}")
            stdin, stdout, stderr = ssh.exec_command(
                "show configuration interfaces | display set | match address"
            )
            output_addr = stdout.read().decode('utf-8', errors='ignore')
            
            # Récupération des descriptions
            logger.info(f"Récupération des descriptions pour {device.name}")
            stdin, stdout, stderr = ssh.exec_command(
                "show configuration interfaces | display set | match description"
            )
            output_desc = stdout.read().decode('utf-8', errors='ignore')
            
            # Récupération des security zones
            logger.info(f"Récupération des security zones pour {device.name}")
            stdin, stdout, stderr = ssh.exec_command(
                "show configuration security zones | display set"
            )
            output_zones = stdout.read().decode('utf-8', errors='ignore')
            
            ssh.close()
            logger.info(f"Connexion SSH fermée pour {device.name}")

            # Mapping des descriptions
            desc_map = {}
            for line in output_desc.splitlines():
                m = re.match(r"set interfaces (\S+) unit (\d+) description (.+)", line)
                if m:
                    iface = m.group(1)
                    unit = m.group(2)
                    desc = m.group(3).strip('"')
                    desc_map[f"{iface}.{unit}"] = desc

            # Parsing des security zones
            for line in output_zones.splitlines():
                m = re.match(r"set security zones security-zone (\S+) interfaces (\S+)", line.strip())
                if m:
                    zone_name = m.group(1)
                    interface_name = m.group(2)
                    
                    # Stocker la zone pour cette interface
                    if interface_name not in security_zones:
                        security_zones[interface_name] = zone_name
                    
                    logger.info(f"Interface {interface_name} associée à la zone {zone_name}")

            # Parsing des interfaces et adresses
            for line in output_addr.splitlines():
                m = re.match(r"set interfaces (\S+) unit (\d+) family inet address (\S+)", line.strip())
                if m:
                    base_iface = m.group(1)
                    unit = m.group(2)
                    iface_full = f"{base_iface}.{unit}"
                    vlan_id = unit
                    ip_addr = m.group(3)
                    desc = desc_map.get(iface_full, f"VLAN{vlan_id}")
                    
                    # Récupérer la security zone pour cette interface
                    zone = security_zones.get(iface_full, None)
                    
                    interfaces.append({
                        "iface_full": iface_full,
                        "vlan_id": vlan_id,
                        "ip_addr": ip_addr,
                        "base_iface": base_iface,
                        "desc": desc,
                        "security_zone": zone,
                    })

            # Calculer les zones uniques
            unique_zones = set([i['security_zone'] for i in interfaces if i['security_zone']])
            zone_count = len(unique_zones)

            if interfaces:
                messages.success(request, f"✓ Scan réussi ! {len(interfaces)} interface(s) et {zone_count} security zone(s) détectée(s).")
                logger.info(f"Scan réussi pour {device.name}: {len(interfaces)} interfaces, {zone_count} zones")
            else:
                messages.warning(request, "Aucune interface avec adresse IP trouvée.")
                logger.warning(f"Aucune interface trouvée pour {device.name}")
            
        except paramiko.AuthenticationException:
            messages.error(request, f"❌ Erreur d'authentification SSH sur {ip}. Vérifiez vos identifiants.")
            logger.error(f"SSH authentication failed for {device.name} ({ip})")
            return redirect('plugins:plugin_juniper:firewall_list')
        except paramiko.SSHException as e:
            messages.error(request, f"❌ Erreur SSH : {str(e)}")
            logger.error(f"SSH error for {device.name} ({ip}): {e}")
            return redirect('plugins:plugin_juniper:firewall_list')
        except Exception as e:
            messages.error(request, f"❌ Erreur lors du scan : {str(e)}")
            logger.error(f"Scan error for {device.name} ({ip}): {e}")
            import traceback
            logger.error(traceback.format_exc())
            return redirect('plugins:plugin_juniper:firewall_list')
        
        # Stockage en session pour la vue 'push'
        request.session['juniper_interfaces'] = interfaces
        request.session['juniper_device_id'] = device.id

        return render(request, "plugin_juniper/interfaces.html", {
            "device": device,
            "interfaces": interfaces,
            "zone_count": zone_count,
            "unique_zones": list(unique_zones),
        })


class FirewallPushView(LoginRequiredMixin, View):
    """Vue d'intégration dans NetBox"""

    def post(self, request, device_id):
        # Récupération des données scannées
        interfaces = request.session.get('juniper_interfaces', [])
        device = get_object_or_404(Device, pk=device_id)
        
        if not interfaces:
            messages.error(request, "Aucune donnée de scan trouvée. Veuillez d'abord scanner l'équipement.")
            return redirect('plugins:plugin_juniper:firewall_list')
        
        tenant = device.tenant
        site = device.site
        results = []
        errors = []
        zones_created = {}

        logger.info(f"Début de l'intégration pour {device.name}: {len(interfaces)} interfaces à traiter")

        # Créer tous les tags de security zones d'abord
        unique_zones = set([i['security_zone'] for i in interfaces if i['security_zone']])
        for zone_name in unique_zones:
            try:
                tag, created = Tag.objects.get_or_create(
                    name=zone_name,
                    defaults={
                        "slug": slugify(zone_name),
                        "description": f"Juniper Security Zone - {zone_name}",
                        "color": "9e9e9e"
                    }
                )
                zones_created[zone_name] = tag
                logger.info(f"Security zone tag '{zone_name}' {'créé' if created else 'existant'}")
            except Exception as e:
                logger.error(f"Erreur lors de la création du tag {zone_name}: {e}")

        for item in interfaces:
            iface_full = item['iface_full']
            vlan_id = item['vlan_id']
            ip_addr = item['ip_addr']
            base_iface = item['base_iface']
            desc = item['desc']
            security_zone = item.get('security_zone')

            try:
                # Création/mise à jour de l'interface
                iface, created = Interface.objects.get_or_create(
                    device=device,
                    name=iface_full,
                    defaults={"type": "virtual", "description": desc}
                )
                if not created and iface.description != desc:
                    iface.description = desc
                    iface.save()
                
                logger.info(f"Interface {iface_full} {'créée' if created else 'mise à jour'}")

                # Associer le tag de security zone à l'interface
                if security_zone and security_zone in zones_created:
                    zone_tag = zones_created[security_zone]
                    if zone_tag not in iface.tags.all():
                        iface.tags.add(zone_tag)
                        logger.info(f"Tag '{security_zone}' ajouté à l'interface {iface_full}")

                # Création/mise à jour du VLAN
                vlan, vlan_created = VLAN.objects.get_or_create(
                    vid=int(vlan_id),
                    site=site,
                    defaults={"name": desc, "tenant": tenant}
                )
                logger.info(f"VLAN {vlan_id} {'créé' if vlan_created else 'existant'}")

                # Création/mise à jour de l'IP
                ip_obj, ip_created = IPAddress.objects.get_or_create(
                    address=ip_addr,
                    defaults={
                        "assigned_object_type": Interface._meta.label_lower.replace('.', ' '),
                        "assigned_object_id": iface.id,
                        "status": "active",
                        "tenant": tenant,
                    }
                )
                
                if not ip_created and not ip_obj.assigned_object_id:
                    ip_obj.assigned_object = iface
                    ip_obj.tenant = tenant
                    ip_obj.save()
                
                logger.info(f"IP {ip_addr} {'créée' if ip_created else 'mise à jour'}")

                # Création du prefix (réseau)
                try:
                    network = ipaddress.IPv4Interface(ip_addr).network
                    prefix_obj, prefix_created = Prefix.objects.get_or_create(
                        prefix=str(network),
                        defaults={
                            "status": "active",
                            "vlan": vlan,
                            "tenant": tenant,
                            "site": site,
                        }
                    )
                    logger.info(f"Prefix {network} {'créé' if prefix_created else 'existant'}")
                except Exception as e:
                    logger.warning(f"Could not create prefix for {ip_addr}: {e}")

                results.append({
                    'interface': iface_full,
                    'ip': ip_addr,
                    'vlan': vlan.vid,
                    'desc': desc,
                    'security_zone': security_zone,
                    'status': 'success'
                })
                
            except Exception as e:
                errors.append({
                    'interface': iface_full,
                    'error': str(e)
                })
                logger.error(f"Error processing interface {iface_full}: {e}")
                import traceback
                logger.error(traceback.format_exc())

        # Nettoyage de la session
        if 'juniper_interfaces' in request.session:
            del request.session['juniper_interfaces']
        if 'juniper_device_id' in request.session:
            del request.session['juniper_device_id']

        if results:
            messages.success(request, f"✓ {len(results)} interface(s) et {len(zones_created)} security zone(s) intégrées avec succès !")
            logger.info(f"Intégration réussie pour {device.name}: {len(results)} éléments, {len(zones_created)} zones")
        if errors:
            messages.warning(request, f"⚠ {len(errors)} erreur(s) lors de l'intégration.")
            logger.warning(f"Intégration avec erreurs pour {device.name}: {len(errors)} erreurs")

        return render(request, "plugin_juniper/push_result.html", {
            "device": device,
            "results": results,
            "errors": errors,
            "zones_created": zones_created,
        })