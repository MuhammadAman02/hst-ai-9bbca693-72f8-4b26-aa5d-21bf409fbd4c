"""Advanced professional visual asset management system with security-focused categories"""

import os
import requests
from typing import Dict, List, Optional
from pathlib import Path
import logging
from urllib.parse import urlparse
import hashlib

logger = logging.getLogger(__name__)

class SecurityAssetManager:
    """Professional asset manager for fraud detection and security applications"""
    
    def __init__(self):
        self.base_path = Path("app/static/images")
        self.base_path.mkdir(parents=True, exist_ok=True)
        
        # Security and fraud detection focused image categories
        self.asset_categories = {
            'security': {
                'shield': [
                    'https://images.unsplash.com/photo-1563013544-824ae1b704d3?w=400&h=400&fit=crop&crop=center',
                    'https://images.unsplash.com/photo-1614064641938-3bbee52942c7?w=400&h=400&fit=crop&crop=center',
                    'https://images.unsplash.com/photo-1550751827-4bd374c3f58b?w=400&h=400&fit=crop&crop=center'
                ],
                'lock': [
                    'https://images.unsplash.com/photo-1614064548237-4d9e5d8e2b39?w=400&h=400&fit=crop&crop=center',
                    'https://images.unsplash.com/photo-1558618666-fcd25c85cd64?w=400&h=400&fit=crop&crop=center',
                    'https://images.unsplash.com/photo-1555949963-aa79dcee981c?w=400&h=400&fit=crop&crop=center'
                ],
                'surveillance': [
                    'https://images.unsplash.com/photo-1557804506-669a67965ba0?w=600&h=400&fit=crop&crop=center',
                    'https://images.unsplash.com/photo-1573164713714-d95e436ab8d6?w=600&h=400&fit=crop&crop=center',
                    'https://images.unsplash.com/photo-1551808525-51a94da548ce?w=600&h=400&fit=crop&crop=center'
                ]
            },
            'financial': {
                'banking': [
                    'https://images.unsplash.com/photo-1556742049-0cfed4f6a45d?w=600&h=400&fit=crop&crop=center',
                    'https://images.unsplash.com/photo-1554224155-6726b3ff858f?w=600&h=400&fit=crop&crop=center',
                    'https://images.unsplash.com/photo-1563013544-824ae1b704d3?w=600&h=400&fit=crop&crop=center'
                ],
                'credit_cards': [
                    'https://images.unsplash.com/photo-1556742502-ec7c0e9f34b1?w=600&h=400&fit=crop&crop=center',
                    'https://images.unsplash.com/photo-1563013544-824ae1b704d3?w=600&h=400&fit=crop&crop=center',
                    'https://images.unsplash.com/photo-1556742049-0cfed4f6a45d?w=600&h=400&fit=crop&crop=center'
                ],
                'money': [
                    'https://images.unsplash.com/photo-1554224155-8d04cb21cd6c?w=600&h=400&fit=crop&crop=center',
                    'https://images.unsplash.com/photo-1579621970563-ebec7560ff3e?w=600&h=400&fit=crop&crop=center',
                    'https://images.unsplash.com/photo-1556742049-0cfed4f6a45d?w=600&h=400&fit=crop&crop=center'
                ]
            },
            'technology': {
                'cybersecurity': [
                    'https://images.unsplash.com/photo-1550751827-4bd374c3f58b?w=800&h=600&fit=crop&crop=center',
                    'https://images.unsplash.com/photo-1563986768609-322da13575f3?w=800&h=600&fit=crop&crop=center',
                    'https://images.unsplash.com/photo-1518709268805-4e9042af2176?w=800&h=600&fit=crop&crop=center'
                ],
                'data_analysis': [
                    'https://images.unsplash.com/photo-1551288049-bebda4e38f71?w=800&h=600&fit=crop&crop=center',
                    'https://images.unsplash.com/photo-1460925895917-afdab827c52f?w=800&h=600&fit=crop&crop=center',
                    'https://images.unsplash.com/photo-1504868584819-f8e8b4b6d7e3?w=800&h=600&fit=crop&crop=center'
                ],
                'monitoring': [
                    'https://images.unsplash.com/photo-1551288049-bebda4e38f71?w=800&h=600&fit=crop&crop=center',
                    'https://images.unsplash.com/photo-1518709268805-4e9042af2176?w=800&h=600&fit=crop&crop=center',
                    'https://images.unsplash.com/photo-1460925895917-afdab827c52f?w=800&h=600&fit=crop&crop=center'
                ]
            },
            'business': {
                'professional': [
                    'https://images.unsplash.com/photo-1507003211169-0a1dd7228f2d?w=600&h=400&fit=crop&crop=center',
                    'https://images.unsplash.com/photo-1573496359142-b8d87734a5a2?w=600&h=400&fit=crop&crop=center',
                    'https://images.unsplash.com/photo-1560250097-0b93528c311a?w=600&h=400&fit=crop&crop=center'
                ],
                'team': [
                    'https://images.unsplash.com/photo-1522071820081-009f0129c71c?w=800&h=600&fit=crop&crop=center',
                    'https://images.unsplash.com/photo-1600880292203-757bb62b4baf?w=800&h=600&fit=crop&crop=center',
                    'https://images.unsplash.com/photo-1556761175-b413da4baf72?w=800&h=600&fit=crop&crop=center'
                ],
                'office': [
                    'https://images.unsplash.com/photo-1497366216548-37526070297c?w=800&h=600&fit=crop&crop=center',
                    'https://images.unsplash.com/photo-1497366754035-f200968a6e72?w=800&h=600&fit=crop&crop=center',
                    'https://images.unsplash.com/photo-1486406146926-c627a92ad1ab?w=800&h=600&fit=crop&crop=center'
                ]
            },
            'alerts': {
                'warning': [
                    'https://images.unsplash.com/photo-1621905252507-b35492cc74b4?w=400&h=400&fit=crop&crop=center',
                    'https://images.unsplash.com/photo-1584464491033-06628f3a6b7b?w=400&h=400&fit=crop&crop=center',
                    'https://images.unsplash.com/photo-1558618666-fcd25c85cd64?w=400&h=400&fit=crop&crop=center'
                ],
                'danger': [
                    'https://images.unsplash.com/photo-1621905252507-b35492cc74b4?w=400&h=400&fit=crop&crop=center',
                    'https://images.unsplash.com/photo-1584464491033-06628f3a6b7b?w=400&h=400&fit=crop&crop=center',
                    'https://images.unsplash.com/photo-1558618666-fcd25c85cd64?w=400&h=400&fit=crop&crop=center'
                ],
                'notification': [
                    'https://images.unsplash.com/photo-1611224923853-80b023f02d71?w=400&h=400&fit=crop&crop=center',
                    'https://images.unsplash.com/photo-1614064641938-3bbee52942c7?w=400&h=400&fit=crop&crop=center',
                    'https://images.unsplash.com/photo-1563013544-824ae1b704d3?w=400&h=400&fit=crop&crop=center'
                ]
            }
        }
        
        # Fallback images for offline use
        self.fallback_images = {
            'shield': 'data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iNDAiIGhlaWdodD0iNDAiIHZpZXdCb3g9IjAgMCA0MCA0MCIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KPHBhdGggZD0iTTIwIDJMMzIgOFYyMEMzMiAyOCAyNiAzNiAyMCAzOEMxNCAzNiA4IDI4IDggMjBWOEwyMCAyWiIgZmlsbD0iIzM0OTdGRiIvPgo8cGF0aCBkPSJNMTYgMjBMMTggMjJMMjQgMTYiIHN0cm9rZT0id2hpdGUiIHN0cm9rZS13aWR0aD0iMiIgc3Ryb2tlLWxpbmVjYXA9InJvdW5kIiBzdHJva2UtbGluZWpvaW49InJvdW5kIi8+Cjwvc3ZnPgo=',
            'lock': 'data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iNDAiIGhlaWdodD0iNDAiIHZpZXdCb3g9IjAgMCA0MCA0MCIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KPHJlY3QgeD0iMTAiIHk9IjE4IiB3aWR0aD0iMjAiIGhlaWdodD0iMTQiIHJ4PSIyIiBmaWxsPSIjRkY2B0I0Ii8+CjxwYXRoIGQ9Ik0xNSAxOFYxMkMxNSA4LjY4NjI5IDE3LjY4NjMgNiAyMSA2QzI0LjMxMzcgNiAyNyA4LjY4NjI5IDI3IDEyVjE4IiBzdHJva2U9IiNGRjZCNDQiIHN0cm9rZS13aWR0aD0iMiIgc3Ryb2tlLWxpbmVjYXA9InJvdW5kIi8+Cjwvc3ZnPgo=',
            'warning': 'data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iNDAiIGhlaWdodD0iNDAiIHZpZXdCb3g9IjAgMCA0MCA0MCIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KPHBhdGggZD0iTTIwIDRMMzYgMzJINEwyMCA0WiIgZmlsbD0iI0ZGQjk0NCIvPgo8cGF0aCBkPSJNMjAgMTJWMjAiIHN0cm9rZT0iIzc5MzUwMyIgc3Ryb2tlLXdpZHRoPSIyIiBzdHJva2UtbGluZWNhcD0icm91bmQiLz4KPGNpcmNsZSBjeD0iMjAiIGN5PSIyNiIgcj0iMSIgZmlsbD0iIzc5MzUwMyIvPgo8L3N2Zz4K'
        }
        
        logger.info("🎨 Security Asset Manager initialized")
    
    def get_security_image(self, image_type: str, index: int = 0) -> str:
        """Get security-related image with fallback"""
        try:
            if image_type in self.asset_categories['security']:
                images = self.asset_categories['security'][image_type]
                if index < len(images):
                    return self._get_image_with_fallback(images[index], f"security_{image_type}_{index}")
            
            # Return fallback SVG if available
            return self.fallback_images.get(image_type, self.fallback_images['shield'])
            
        except Exception as e:
            logger.error(f"Error getting security image: {e}")
            return self.fallback_images.get(image_type, self.fallback_images['shield'])
    
    def get_financial_image(self, image_type: str, index: int = 0) -> str:
        """Get financial-related image with fallback"""
        try:
            if image_type in self.asset_categories['financial']:
                images = self.asset_categories['financial'][image_type]
                if index < len(images):
                    return self._get_image_with_fallback(images[index], f"financial_{image_type}_{index}")
            
            return self.fallback_images.get('shield')  # Default fallback
            
        except Exception as e:
            logger.error(f"Error getting financial image: {e}")
            return self.fallback_images.get('shield')
    
    def get_technology_image(self, image_type: str, index: int = 0) -> str:
        """Get technology-related image with fallback"""
        try:
            if image_type in self.asset_categories['technology']:
                images = self.asset_categories['technology'][image_type]
                if index < len(images):
                    return self._get_image_with_fallback(images[index], f"technology_{image_type}_{index}")
            
            return self.fallback_images.get('shield')  # Default fallback
            
        except Exception as e:
            logger.error(f"Error getting technology image: {e}")
            return self.fallback_images.get('shield')
    
    def get_business_image(self, image_type: str, index: int = 0) -> str:
        """Get business-related image with fallback"""
        try:
            if image_type in self.asset_categories['business']:
                images = self.asset_categories['business'][image_type]
                if index < len(images):
                    return self._get_image_with_fallback(images[index], f"business_{image_type}_{index}")
            
            return self.fallback_images.get('shield')  # Default fallback
            
        except Exception as e:
            logger.error(f"Error getting business image: {e}")
            return self.fallback_images.get('shield')
    
    def get_alert_image(self, image_type: str, index: int = 0) -> str:
        """Get alert-related image with fallback"""
        try:
            if image_type in self.asset_categories['alerts']:
                images = self.asset_categories['alerts'][image_type]
                if index < len(images):
                    return self._get_image_with_fallback(images[index], f"alert_{image_type}_{index}")
            
            return self.fallback_images.get(image_type, self.fallback_images['warning'])
            
        except Exception as e:
            logger.error(f"Error getting alert image: {e}")
            return self.fallback_images.get(image_type, self.fallback_images['warning'])
    
    def _get_image_with_fallback(self, url: str, cache_key: str) -> str:
        """Get image with local caching and fallback"""
        try:
            # Generate filename from URL hash
            url_hash = hashlib.md5(url.encode()).hexdigest()
            filename = f"{cache_key}_{url_hash}.jpg"
            local_path = self.base_path / filename
            
            # Return local file if it exists
            if local_path.exists():
                return f"/static/images/{filename}"
            
            # Try to download and cache the image
            response = requests.get(url, timeout=10, headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            })
            
            if response.status_code == 200:
                with open(local_path, 'wb') as f:
                    f.write(response.content)
                logger.info(f"✅ Cached image: {filename}")
                return f"/static/images/{filename}"
            else:
                logger.warning(f"⚠️ Failed to download image: {url} (Status: {response.status_code})")
                return url  # Return original URL as fallback
                
        except Exception as e:
            logger.error(f"❌ Error caching image {url}: {e}")
            return url  # Return original URL as fallback
    
    def get_hero_background(self, theme: str = 'security') -> str:
        """Get hero section background image"""
        hero_images = {
            'security': 'https://images.unsplash.com/photo-1550751827-4bd374c3f58b?w=1920&h=1080&fit=crop&crop=center',
            'financial': 'https://images.unsplash.com/photo-1556742049-0cfed4f6a45d?w=1920&h=1080&fit=crop&crop=center',
            'technology': 'https://images.unsplash.com/photo-1518709268805-4e9042af2176?w=1920&h=1080&fit=crop&crop=center',
            'business': 'https://images.unsplash.com/photo-1497366216548-37526070297c?w=1920&h=1080&fit=crop&crop=center'
        }
        
        return self._get_image_with_fallback(
            hero_images.get(theme, hero_images['security']),
            f"hero_{theme}"
        )
    
    def get_dashboard_icons(self) -> Dict[str, str]:
        """Get dashboard icon set"""
        return {
            'transactions': '💳',
            'alerts': '🚨',
            'cases': '📋',
            'rules': '⚙️',
            'users': '👥',
            'reports': '📊',
            'settings': '⚙️',
            'security': '🔒',
            'monitoring': '👁️',
            'analysis': '🔍'
        }
    
    def get_status_colors(self) -> Dict[str, str]:
        """Get status color scheme for fraud detection"""
        return {
            'high_risk': '#ff4757',      # Red
            'medium_risk': '#ffa502',    # Orange
            'low_risk': '#2ed573',       # Green
            'normal': '#70a1ff',         # Blue
            'flagged': '#ff4757',        # Red
            'resolved': '#2ed573',       # Green
            'in_progress': '#ffa502',    # Orange
            'open': '#ff6b6b',          # Light Red
            'closed': '#a4b0be'         # Gray
        }
    
    def preload_critical_assets(self):
        """Preload critical assets for better performance"""
        critical_assets = [
            ('security', 'shield', 0),
            ('security', 'lock', 0),
            ('alerts', 'warning', 0),
            ('alerts', 'danger', 0),
            ('technology', 'cybersecurity', 0),
            ('financial', 'banking', 0)
        ]
        
        logger.info("🚀 Preloading critical assets...")
        for category, image_type, index in critical_assets:
            try:
                if category == 'security':
                    self.get_security_image(image_type, index)
                elif category == 'alerts':
                    self.get_alert_image(image_type, index)
                elif category == 'technology':
                    self.get_technology_image(image_type, index)
                elif category == 'financial':
                    self.get_financial_image(image_type, index)
            except Exception as e:
                logger.error(f"Error preloading {category}/{image_type}: {e}")
        
        logger.info("✅ Critical assets preloaded")
    
    def cleanup_old_cache(self, days: int = 30):
        """Clean up old cached images"""
        try:
            import time
            cutoff_time = time.time() - (days * 24 * 60 * 60)
            
            for image_file in self.base_path.glob("*.jpg"):
                if image_file.stat().st_mtime < cutoff_time:
                    image_file.unlink()
                    logger.info(f"🗑️ Cleaned up old cache file: {image_file.name}")
                    
        except Exception as e:
            logger.error(f"Error cleaning up cache: {e}")