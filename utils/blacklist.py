import ipaddress
import os
import logging

class BlacklistFilter:
    """
    Module lọc mục tiêu dựa trên Blacklist (CIDR, IP, Regex).
    Lấy cảm hứng từ xingrin/database_provider.py
    """
    def __init__(self, blacklist_file: str = None):
        self.rules = []
        if blacklist_file and os.path.exists(blacklist_file):
            with open(blacklist_file, 'r') as f:
                self.rules = [line.strip() for line in f if line.strip() and not line.startswith('#')]

    def is_allowed(self, target: str) -> bool:
        """Kiểm tra target có nằm trong blacklist không."""
        if not self.rules:
            return True
            
        for rule in self.rules:
            # Check exact match
            if target == rule:
                return False
                
            # Check CIDR
            if '/' in rule:
                try:
                    target_ip = ipaddress.ip_address(target)
                    network = ipaddress.ip_network(rule, strict=False)
                    if target_ip in network:
                        return False
                except ValueError:
                    pass
                    
            # Check domain suffix (*.blacklist.com -> blacklist.com)
            stripped_rule = rule.lstrip('*.')
            if target == stripped_rule or target.endswith('.' + stripped_rule):
                return False
                
        return True
