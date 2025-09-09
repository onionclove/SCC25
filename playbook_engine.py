import yaml

def get_playbook(description):
    with open("playbooks.yaml") as f:
        playbooks = yaml.safe_load(f)
    for pb in playbooks:
        if pb["trigger"].lower() in description.lower():
            return pb
    return None
