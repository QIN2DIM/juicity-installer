# Ansible Install

## Get started

### Local deploy

1. Modify the `kvm.hosts.localhost.juicity_domain` field of `inventory.yaml` to the domain name of IPv4 resolved to the localhost. 

2. Run the following command to install juicity-server in the localhost
```bash
# /path/to/juicity-installer/ansible
ansible-playbook local_deploy.yaml
```

### Check configuration of client outbound

| Implement                                              | Command                                  |
| ------------------------------------------------------ | ---------------------------------------- |
| [NekoRay](https://matsuridayo.github.io/n-extra_core/) | `more /home/juicity/nekoray_config.json` |
|                                                        |                                          |
|                                                        |                                          |

### Check runtime-config of juicity-server

```
more /home/juicity/server.json
```

