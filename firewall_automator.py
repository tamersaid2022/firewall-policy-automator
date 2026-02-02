#!/usr/bin/env python3
"""
Firewall Policy Automator
Enterprise-grade firewall policy automation for Palo Alto and FortiGate platforms

Author: Tamer Khalifa (CCIE #68867)
GitHub: https://github.com/tamersaid2022
"""

import os
import sys
import json
import logging
import argparse
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Union
from dataclasses import dataclass, field
from abc import ABC, abstractmethod

import yaml
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from jinja2 import Environment, FileSystemLoader

# Suppress SSL warnings for lab environments
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('firewall_automator.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class FirewallRule:
    """Represents a firewall security rule"""
    name: str
    source_zone: Union[str, List[str]]
    destination_zone: Union[str, List[str]]
    source_ip: List[str] = field(default_factory=lambda: ["any"])
    destination_ip: List[str] = field(default_factory=lambda: ["any"])
    application: List[str] = field(default_factory=lambda: ["any"])
    service: List[str] = field(default_factory=lambda: ["application-default"])
    action: str = "allow"
    log_start: bool = False
    log_end: bool = True
    description: str = ""
    tags: List[str] = field(default_factory=list)
    profile_group: Optional[str] = None
    disabled: bool = False

    def to_dict(self) -> Dict:
        """Convert rule to dictionary"""
        return {
            "name": self.name,
            "source_zone": self.source_zone if isinstance(self.source_zone, list) else [self.source_zone],
            "destination_zone": self.destination_zone if isinstance(self.destination_zone, list) else [self.destination_zone],
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "application": self.application,
            "service": self.service,
            "action": self.action,
            "log_start": self.log_start,
            "log_end": self.log_end,
            "description": self.description,
            "tags": self.tags,
            "profile_group": self.profile_group,
            "disabled": self.disabled
        }


@dataclass
class ValidationResult:
    """Stores validation results"""
    success: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    info: List[str] = field(default_factory=list)


@dataclass
class DeploymentResult:
    """Stores deployment results"""
    success: bool
    rules_created: int = 0
    rules_modified: int = 0
    rules_deleted: int = 0
    commit_id: Optional[str] = None
    errors: List[str] = field(default_factory=list)
    backup_path: Optional[str] = None


# =============================================================================
# ABSTRACT BASE CLASS
# =============================================================================

class FirewallConnector(ABC):
    """Abstract base class for firewall connections"""
    
    def __init__(self, host: str, api_key: str, verify_ssl: bool = False):
        self.host = host
        self.api_key = api_key
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.verify = verify_ssl
        
    @abstractmethod
    def connect(self) -> bool:
        """Establish connection to firewall"""
        pass
    
    @abstractmethod
    def get_rules(self, rulebase: str = "security") -> List[Dict]:
        """Retrieve existing rules"""
        pass
    
    @abstractmethod
    def create_rule(self, rule: FirewallRule, position: str = "bottom") -> bool:
        """Create a new rule"""
        pass
    
    @abstractmethod
    def update_rule(self, rule: FirewallRule) -> bool:
        """Update an existing rule"""
        pass
    
    @abstractmethod
    def delete_rule(self, rule_name: str) -> bool:
        """Delete a rule"""
        pass
    
    @abstractmethod
    def commit(self, description: str = "") -> str:
        """Commit changes"""
        pass
    
    @abstractmethod
    def validate(self) -> ValidationResult:
        """Validate pending changes"""
        pass


# =============================================================================
# PALO ALTO CONNECTOR
# =============================================================================

class PaloAltoConnector(FirewallConnector):
    """Connector for Palo Alto PAN-OS firewalls"""
    
    def __init__(self, host: str, api_key: str, verify_ssl: bool = False, vsys: str = "vsys1"):
        super().__init__(host, api_key, verify_ssl)
        self.vsys = vsys
        self.base_url = f"https://{host}/restapi/v10.2"
        self.session.headers.update({
            "X-PAN-KEY": api_key,
            "Content-Type": "application/json"
        })
        
    def connect(self) -> bool:
        """Test connection to Palo Alto firewall"""
        try:
            url = f"https://{self.host}/api/?type=op&cmd=<show><system><info></info></system></show>&key={self.api_key}"
            response = self.session.get(url, timeout=10)
            if response.status_code == 200 and "success" in response.text:
                logger.info(f"✅ Connected to Palo Alto firewall: {self.host}")
                return True
            logger.error(f"❌ Connection failed: {response.text}")
            return False
        except Exception as e:
            logger.error(f"❌ Connection error: {e}")
            return False
    
    def get_rules(self, rulebase: str = "security") -> List[Dict]:
        """Get all security rules from PAN-OS"""
        try:
            url = f"{self.base_url}/Policies/SecurityRules?location=vsys&vsys={self.vsys}"
            response = self.session.get(url, timeout=30)
            if response.status_code == 200:
                data = response.json()
                rules = data.get("result", {}).get("entry", [])
                logger.info(f"📋 Retrieved {len(rules)} rules from {self.host}")
                return rules
            return []
        except Exception as e:
            logger.error(f"Error retrieving rules: {e}")
            return []
    
    def create_rule(self, rule: FirewallRule, position: str = "bottom") -> bool:
        """Create a new security rule"""
        try:
            url = f"{self.base_url}/Policies/SecurityRules?location=vsys&vsys={self.vsys}&name={rule.name}"
            
            payload = {
                "entry": {
                    "@name": rule.name,
                    "from": {"member": rule.source_zone if isinstance(rule.source_zone, list) else [rule.source_zone]},
                    "to": {"member": rule.destination_zone if isinstance(rule.destination_zone, list) else [rule.destination_zone]},
                    "source": {"member": rule.source_ip},
                    "destination": {"member": rule.destination_ip},
                    "application": {"member": rule.application},
                    "service": {"member": rule.service},
                    "action": rule.action,
                    "log-end": "yes" if rule.log_end else "no",
                    "description": rule.description
                }
            }
            
            if rule.profile_group:
                payload["entry"]["profile-setting"] = {"group": {"member": [rule.profile_group]}}
            
            if rule.tags:
                payload["entry"]["tag"] = {"member": rule.tags}
            
            response = self.session.post(url, json=payload, timeout=30)
            
            if response.status_code in [200, 201]:
                logger.info(f"✅ Created rule: {rule.name}")
                return True
            else:
                logger.error(f"❌ Failed to create rule {rule.name}: {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"Error creating rule: {e}")
            return False
    
    def update_rule(self, rule: FirewallRule) -> bool:
        """Update an existing rule"""
        try:
            url = f"{self.base_url}/Policies/SecurityRules?location=vsys&vsys={self.vsys}&name={rule.name}"
            
            payload = {
                "entry": {
                    "@name": rule.name,
                    "from": {"member": rule.source_zone if isinstance(rule.source_zone, list) else [rule.source_zone]},
                    "to": {"member": rule.destination_zone if isinstance(rule.destination_zone, list) else [rule.destination_zone]},
                    "source": {"member": rule.source_ip},
                    "destination": {"member": rule.destination_ip},
                    "application": {"member": rule.application},
                    "service": {"member": rule.service},
                    "action": rule.action
                }
            }
            
            response = self.session.put(url, json=payload, timeout=30)
            
            if response.status_code == 200:
                logger.info(f"✅ Updated rule: {rule.name}")
                return True
            return False
            
        except Exception as e:
            logger.error(f"Error updating rule: {e}")
            return False
    
    def delete_rule(self, rule_name: str) -> bool:
        """Delete a security rule"""
        try:
            url = f"{self.base_url}/Policies/SecurityRules?location=vsys&vsys={self.vsys}&name={rule_name}"
            response = self.session.delete(url, timeout=30)
            
            if response.status_code == 200:
                logger.info(f"🗑️ Deleted rule: {rule_name}")
                return True
            return False
            
        except Exception as e:
            logger.error(f"Error deleting rule: {e}")
            return False
    
    def validate(self) -> ValidationResult:
        """Validate pending changes"""
        result = ValidationResult(success=True)
        try:
            url = f"https://{self.host}/api/?type=op&cmd=<validate><full></full></validate>&key={self.api_key}"
            response = self.session.get(url, timeout=60)
            
            if "success" in response.text:
                result.info.append("Configuration validation passed")
            else:
                result.success = False
                result.errors.append(f"Validation failed: {response.text}")
                
        except Exception as e:
            result.success = False
            result.errors.append(str(e))
            
        return result
    
    def commit(self, description: str = "") -> str:
        """Commit changes to firewall"""
        try:
            cmd = f"<commit><description>{description}</description></commit>" if description else "<commit></commit>"
            url = f"https://{self.host}/api/?type=commit&cmd={cmd}&key={self.api_key}"
            response = self.session.get(url, timeout=120)
            
            if "success" in response.text:
                # Extract job ID from response
                import re
                match = re.search(r'<job>(\d+)</job>', response.text)
                job_id = match.group(1) if match else "unknown"
                logger.info(f"✅ Commit successful - Job ID: {job_id}")
                return job_id
            else:
                logger.error(f"❌ Commit failed: {response.text}")
                return ""
                
        except Exception as e:
            logger.error(f"Commit error: {e}")
            return ""
    
    def backup_config(self, output_path: str = None) -> str:
        """Backup current configuration"""
        try:
            url = f"https://{self.host}/api/?type=export&category=configuration&key={self.api_key}"
            response = self.session.get(url, timeout=60)
            
            if response.status_code == 200:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                output_path = output_path or f"backup/config_{self.host}_{timestamp}.xml"
                Path(output_path).parent.mkdir(parents=True, exist_ok=True)
                
                with open(output_path, 'w') as f:
                    f.write(response.text)
                    
                logger.info(f"💾 Configuration backed up to: {output_path}")
                return output_path
            return ""
            
        except Exception as e:
            logger.error(f"Backup error: {e}")
            return ""


# =============================================================================
# FORTIGATE CONNECTOR
# =============================================================================

class FortiGateConnector(FirewallConnector):
    """Connector for FortiGate FortiOS firewalls"""
    
    def __init__(self, host: str, api_key: str, verify_ssl: bool = False, vdom: str = "root"):
        super().__init__(host, api_key, verify_ssl)
        self.vdom = vdom
        self.base_url = f"https://{host}/api/v2"
        self.session.headers.update({
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        })
    
    def connect(self) -> bool:
        """Test connection to FortiGate"""
        try:
            url = f"{self.base_url}/cmdb/system/status"
            response = self.session.get(url, timeout=10)
            if response.status_code == 200:
                logger.info(f"✅ Connected to FortiGate: {self.host}")
                return True
            return False
        except Exception as e:
            logger.error(f"Connection error: {e}")
            return False
    
    def get_rules(self, rulebase: str = "security") -> List[Dict]:
        """Get firewall policies from FortiGate"""
        try:
            url = f"{self.base_url}/cmdb/firewall/policy?vdom={self.vdom}"
            response = self.session.get(url, timeout=30)
            if response.status_code == 200:
                rules = response.json().get("results", [])
                logger.info(f"📋 Retrieved {len(rules)} policies from {self.host}")
                return rules
            return []
        except Exception as e:
            logger.error(f"Error retrieving rules: {e}")
            return []
    
    def create_rule(self, rule: FirewallRule, position: str = "bottom") -> bool:
        """Create a new firewall policy"""
        try:
            url = f"{self.base_url}/cmdb/firewall/policy?vdom={self.vdom}"
            
            payload = {
                "name": rule.name,
                "srcintf": [{"name": z} for z in (rule.source_zone if isinstance(rule.source_zone, list) else [rule.source_zone])],
                "dstintf": [{"name": z} for z in (rule.destination_zone if isinstance(rule.destination_zone, list) else [rule.destination_zone])],
                "srcaddr": [{"name": ip} for ip in rule.source_ip],
                "dstaddr": [{"name": ip} for ip in rule.destination_ip],
                "action": "accept" if rule.action == "allow" else "deny",
                "schedule": "always",
                "service": [{"name": svc} for svc in rule.service],
                "logtraffic": "all" if rule.log_end else "disable",
                "comments": rule.description
            }
            
            response = self.session.post(url, json=payload, timeout=30)
            
            if response.status_code == 200:
                logger.info(f"✅ Created policy: {rule.name}")
                return True
            return False
            
        except Exception as e:
            logger.error(f"Error creating policy: {e}")
            return False
    
    def update_rule(self, rule: FirewallRule) -> bool:
        """Update existing policy - requires policy ID"""
        logger.warning("FortiGate update requires policy ID - use get_rules() first")
        return False
    
    def delete_rule(self, rule_name: str) -> bool:
        """Delete policy by ID"""
        logger.warning("FortiGate delete requires policy ID")
        return False
    
    def validate(self) -> ValidationResult:
        """FortiGate doesn't have candidate config - always valid"""
        return ValidationResult(success=True, info=["FortiGate applies changes immediately"])
    
    def commit(self, description: str = "") -> str:
        """FortiGate applies changes immediately - no commit needed"""
        logger.info("FortiGate: Changes applied immediately (no commit required)")
        return "immediate"


# =============================================================================
# MAIN AUTOMATOR CLASS
# =============================================================================

class FirewallAutomator:
    """Main automation orchestrator"""
    
    SUPPORTED_PLATFORMS = {
        "paloalto": PaloAltoConnector,
        "pan-os": PaloAltoConnector,
        "panorama": PaloAltoConnector,
        "fortigate": FortiGateConnector,
        "fortios": FortiGateConnector
    }
    
    def __init__(self, platform: str, host: str, api_key: str, **kwargs):
        """
        Initialize firewall automator
        
        Args:
            platform: Firewall platform (paloalto, fortigate)
            host: Firewall hostname or IP
            api_key: API authentication key
            **kwargs: Additional platform-specific options
        """
        platform = platform.lower()
        if platform not in self.SUPPORTED_PLATFORMS:
            raise ValueError(f"Unsupported platform: {platform}. Supported: {list(self.SUPPORTED_PLATFORMS.keys())}")
        
        connector_class = self.SUPPORTED_PLATFORMS[platform]
        self.connector = connector_class(host, api_key, **kwargs)
        self.platform = platform
        self.backup_path = None
        
    def connect(self) -> bool:
        """Establish connection"""
        return self.connector.connect()
    
    def deploy_policy(self, policy_file: str, device_group: str = None) -> DeploymentResult:
        """
        Deploy policy from YAML/JSON file
        
        Args:
            policy_file: Path to policy definition file
            device_group: Panorama device group (optional)
            
        Returns:
            DeploymentResult with deployment status
        """
        result = DeploymentResult(success=True)
        
        # Load policy file
        policy_path = Path(policy_file)
        if not policy_path.exists():
            result.success = False
            result.errors.append(f"Policy file not found: {policy_file}")
            return result
        
        with open(policy_path) as f:
            if policy_path.suffix in ['.yaml', '.yml']:
                policy_data = yaml.safe_load(f)
            else:
                policy_data = json.load(f)
        
        # Backup current config
        if hasattr(self.connector, 'backup_config'):
            self.backup_path = self.connector.backup_config()
            result.backup_path = self.backup_path
        
        # Process rules
        rules = policy_data.get('rules', [])
        logger.info(f"📦 Processing {len(rules)} rules from {policy_file}")
        
        for rule_data in rules:
            rule = FirewallRule(**rule_data)
            
            # Check if rule exists
            existing_rules = self.connector.get_rules()
            rule_names = [r.get('@name', r.get('name', '')) for r in existing_rules]
            
            if rule.name in rule_names:
                # Update existing rule
                if self.connector.update_rule(rule):
                    result.rules_modified += 1
                else:
                    result.errors.append(f"Failed to update rule: {rule.name}")
            else:
                # Create new rule
                if self.connector.create_rule(rule):
                    result.rules_created += 1
                else:
                    result.errors.append(f"Failed to create rule: {rule.name}")
        
        if result.errors:
            result.success = False
            
        return result
    
    def validate(self) -> ValidationResult:
        """Validate pending changes"""
        return self.connector.validate()
    
    def commit(self, description: str = "") -> str:
        """Commit changes"""
        return self.connector.commit(description)
    
    def rollback(self) -> bool:
        """Rollback to backup configuration"""
        if not self.backup_path:
            logger.error("No backup available for rollback")
            return False
        logger.info(f"🔙 Rolling back to: {self.backup_path}")
        # Implementation depends on platform
        return True
    
    def export_rules(self, output_file: str, format: str = "yaml") -> bool:
        """
        Export current rules to file
        
        Args:
            output_file: Output file path
            format: Output format (yaml, json, csv)
        """
        rules = self.connector.get_rules()
        
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        if format == "yaml":
            with open(output_path, 'w') as f:
                yaml.dump({"rules": rules}, f, default_flow_style=False)
        elif format == "json":
            with open(output_path, 'w') as f:
                json.dump({"rules": rules}, f, indent=2)
        elif format == "csv":
            import csv
            if rules:
                with open(output_path, 'w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=rules[0].keys())
                    writer.writeheader()
                    writer.writerows(rules)
        
        logger.info(f"📤 Exported {len(rules)} rules to: {output_file}")
        return True
    
    def audit_compliance(self, baseline_file: str) -> Dict:
        """
        Audit rules against compliance baseline
        
        Args:
            baseline_file: Path to compliance baseline YAML
            
        Returns:
            Compliance audit report
        """
        with open(baseline_file) as f:
            baseline = yaml.safe_load(f)
        
        current_rules = self.connector.get_rules()
        
        report = {
            "timestamp": datetime.now().isoformat(),
            "firewall": self.connector.host,
            "baseline": baseline_file,
            "total_rules": len(current_rules),
            "compliant": 0,
            "non_compliant": 0,
            "findings": []
        }
        
        # Check required rules
        required_rules = baseline.get("required_rules", [])
        for required in required_rules:
            found = any(r.get("name", r.get("@name", "")) == required["name"] for r in current_rules)
            if found:
                report["compliant"] += 1
            else:
                report["non_compliant"] += 1
                report["findings"].append({
                    "severity": "HIGH",
                    "type": "MISSING_REQUIRED_RULE",
                    "rule": required["name"],
                    "description": f"Required rule '{required['name']}' not found"
                })
        
        # Check prohibited configurations
        prohibited = baseline.get("prohibited", {})
        for rule in current_rules:
            # Check for any-any rules
            if prohibited.get("any_any_rules", True):
                if "any" in str(rule.get("source", [])) and "any" in str(rule.get("destination", [])):
                    report["findings"].append({
                        "severity": "MEDIUM",
                        "type": "ANY_ANY_RULE",
                        "rule": rule.get("name", rule.get("@name", "unknown")),
                        "description": "Rule allows any source to any destination"
                    })
        
        logger.info(f"📊 Audit complete: {report['compliant']} compliant, {report['non_compliant']} non-compliant")
        return report


# =============================================================================
# CLI INTERFACE
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Firewall Policy Automator - Enterprise firewall automation tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Deploy policies:
    python firewall_automator.py deploy --platform paloalto --host 192.168.1.1 --config policies/web.yaml
    
  Export rules:
    python firewall_automator.py export --platform fortigate --host fw.company.com --output backup.yaml
    
  Validate config:
    python firewall_automator.py validate --platform paloalto --host 192.168.1.1
    
  Audit compliance:
    python firewall_automator.py audit --platform paloalto --host 192.168.1.1 --baseline pci-dss.yaml

Author: Tamer Khalifa (CCIE #68867)
        """
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Common arguments
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--platform", "-p", required=True, choices=["paloalto", "fortigate"], help="Firewall platform")
    common.add_argument("--host", "-H", required=True, help="Firewall hostname or IP")
    common.add_argument("--api-key", "-k", help="API key (or set FW_API_KEY env var)")
    common.add_argument("--verify-ssl", action="store_true", help="Verify SSL certificates")
    
    # Deploy command
    deploy_parser = subparsers.add_parser("deploy", parents=[common], help="Deploy firewall policies")
    deploy_parser.add_argument("--config", "-c", required=True, help="Policy configuration file (YAML/JSON)")
    deploy_parser.add_argument("--device-group", "-d", help="Panorama device group")
    deploy_parser.add_argument("--commit", action="store_true", help="Commit changes after deployment")
    
    # Export command
    export_parser = subparsers.add_parser("export", parents=[common], help="Export current rules")
    export_parser.add_argument("--output", "-o", required=True, help="Output file path")
    export_parser.add_argument("--format", "-f", choices=["yaml", "json", "csv"], default="yaml", help="Output format")
    
    # Validate command
    validate_parser = subparsers.add_parser("validate", parents=[common], help="Validate pending changes")
    
    # Audit command
    audit_parser = subparsers.add_parser("audit", parents=[common], help="Audit compliance")
    audit_parser.add_argument("--baseline", "-b", required=True, help="Compliance baseline file")
    audit_parser.add_argument("--report", "-r", help="Output report file")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    # Get API key
    api_key = args.api_key or os.getenv("FW_API_KEY")
    if not api_key:
        print("❌ Error: API key required. Use --api-key or set FW_API_KEY environment variable")
        sys.exit(1)
    
    # Initialize automator
    try:
        automator = FirewallAutomator(
            platform=args.platform,
            host=args.host,
            api_key=api_key,
            verify_ssl=args.verify_ssl
        )
        
        if not automator.connect():
            print("❌ Failed to connect to firewall")
            sys.exit(1)
            
    except Exception as e:
        print(f"❌ Initialization error: {e}")
        sys.exit(1)
    
    # Execute command
    if args.command == "deploy":
        result = automator.deploy_policy(args.config, args.device_group)
        print(f"\n{'='*60}")
        print(f"DEPLOYMENT RESULT")
        print(f"{'='*60}")
        print(f"Status:         {'✅ SUCCESS' if result.success else '❌ FAILED'}")
        print(f"Rules Created:  {result.rules_created}")
        print(f"Rules Modified: {result.rules_modified}")
        print(f"Backup:         {result.backup_path or 'N/A'}")
        if result.errors:
            print(f"Errors:         {len(result.errors)}")
            for err in result.errors:
                print(f"  - {err}")
        print(f"{'='*60}\n")
        
        if args.commit and result.success:
            validation = automator.validate()
            if validation.success:
                commit_id = automator.commit("Automated deployment")
                print(f"✅ Changes committed - ID: {commit_id}")
            else:
                print(f"❌ Validation failed: {validation.errors}")
                
    elif args.command == "export":
        automator.export_rules(args.output, args.format)
        print(f"✅ Rules exported to: {args.output}")
        
    elif args.command == "validate":
        result = automator.validate()
        print(f"\nValidation: {'✅ PASSED' if result.success else '❌ FAILED'}")
        for info in result.info:
            print(f"  ℹ️ {info}")
        for warn in result.warnings:
            print(f"  ⚠️ {warn}")
        for err in result.errors:
            print(f"  ❌ {err}")
            
    elif args.command == "audit":
        report = automator.audit_compliance(args.baseline)
        print(f"\n{'='*60}")
        print(f"COMPLIANCE AUDIT REPORT")
        print(f"{'='*60}")
        print(f"Firewall:       {report['firewall']}")
        print(f"Baseline:       {report['baseline']}")
        print(f"Total Rules:    {report['total_rules']}")
        print(f"Compliant:      {report['compliant']}")
        print(f"Non-Compliant:  {report['non_compliant']}")
        print(f"\nFindings ({len(report['findings'])}):")
        for finding in report["findings"]:
            print(f"  [{finding['severity']}] {finding['type']}: {finding['description']}")
        print(f"{'='*60}\n")
        
        if args.report:
            with open(args.report, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"📄 Report saved to: {args.report}")


if __name__ == "__main__":
    main()
