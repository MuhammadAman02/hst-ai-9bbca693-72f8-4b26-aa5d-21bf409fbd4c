"""
Advanced fraud detection engine with configurable rules and ML scoring
Handles real-time transaction analysis and risk assessment
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
import json
import math
from collections import defaultdict, deque

from .database import SessionLocal, Transaction, FraudRule, Alert
from .config import settings

logger = logging.getLogger(__name__)

@dataclass
class RiskFactor:
    """Individual risk factor with score and description"""
    name: str
    score: float
    description: str
    severity: str  # low, medium, high

@dataclass
class FraudAssessment:
    """Complete fraud assessment result"""
    transaction_id: int
    total_risk_score: float
    risk_level: str  # low, medium, high
    risk_factors: List[RiskFactor]
    triggered_rules: List[int]
    recommendations: List[str]
    requires_manual_review: bool

class FraudDetectionEngine:
    """Advanced fraud detection engine with multiple detection strategies"""
    
    def __init__(self):
        self.is_running = False
        self.transaction_cache = defaultdict(deque)  # User transaction history cache
        self.velocity_windows = defaultdict(list)    # Velocity tracking
        self.risk_patterns = {}                      # Learned risk patterns
        self.active_rules = []                       # Cached active rules
        
        # Risk scoring weights
        self.risk_weights = {
            'amount': 0.25,
            'velocity': 0.20,
            'geographic': 0.15,
            'temporal': 0.10,
            'device': 0.10,
            'behavioral': 0.20
        }
        
        # Geographic risk mapping
        self.country_risk_scores = {
            'US': 0.1, 'CA': 0.1, 'GB': 0.1, 'DE': 0.1, 'FR': 0.1,
            'XX': 0.9, 'YY': 0.8, 'ZZ': 0.7  # High-risk countries
        }
        
        logger.info("🔒 Fraud Detection Engine initialized")
    
    async def start(self):
        """Start the fraud detection engine"""
        self.is_running = True
        await self.load_active_rules()
        await self.initialize_caches()
        logger.info("✅ Fraud Detection Engine started")
    
    async def stop(self):
        """Stop the fraud detection engine"""
        self.is_running = False
        logger.info("🛑 Fraud Detection Engine stopped")
    
    async def load_active_rules(self):
        """Load active fraud detection rules from database"""
        try:
            db = SessionLocal()
            rules = db.query(FraudRule).filter(FraudRule.is_active == True).all()
            self.active_rules = [
                {
                    'id': rule.id,
                    'name': rule.name,
                    'rule_type': rule.rule_type,
                    'conditions': rule.conditions,
                    'threshold': rule.threshold,
                    'priority': rule.priority
                }
                for rule in rules
            ]
            db.close()
            logger.info(f"📋 Loaded {len(self.active_rules)} active fraud rules")
        except Exception as e:
            logger.error(f"❌ Error loading fraud rules: {e}")
    
    async def initialize_caches(self):
        """Initialize transaction caches for velocity and pattern detection"""
        try:
            db = SessionLocal()
            # Load recent transactions for velocity analysis
            cutoff_time = datetime.now() - timedelta(hours=24)
            recent_transactions = db.query(Transaction).filter(
                Transaction.timestamp >= cutoff_time
            ).all()
            
            for transaction in recent_transactions:
                self.transaction_cache[transaction.user_id].append({
                    'id': transaction.id,
                    'amount': transaction.amount,
                    'timestamp': transaction.timestamp,
                    'location': transaction.location,
                    'country_code': transaction.country_code,
                    'device_id': transaction.device_id
                })
            
            db.close()
            logger.info(f"💾 Initialized caches with {len(recent_transactions)} recent transactions")
        except Exception as e:
            logger.error(f"❌ Error initializing caches: {e}")
    
    async def analyze_transaction(self, transaction_data: Dict[str, Any]) -> FraudAssessment:
        """Perform comprehensive fraud analysis on a transaction"""
        try:
            # Extract transaction details
            transaction_id = transaction_data.get('id')
            user_id = transaction_data.get('user_id')
            amount = transaction_data.get('amount', 0)
            timestamp = transaction_data.get('timestamp', datetime.now())
            
            risk_factors = []
            triggered_rules = []
            
            # 1. Amount-based risk analysis
            amount_risk = await self._analyze_amount_risk(amount, user_id)
            if amount_risk:
                risk_factors.append(amount_risk)
            
            # 2. Velocity analysis
            velocity_risk = await self._analyze_velocity_risk(user_id, timestamp)
            if velocity_risk:
                risk_factors.append(velocity_risk)
            
            # 3. Geographic risk analysis
            geographic_risk = await self._analyze_geographic_risk(transaction_data)
            if geographic_risk:
                risk_factors.append(geographic_risk)
            
            # 4. Temporal pattern analysis
            temporal_risk = await self._analyze_temporal_risk(timestamp, user_id)
            if temporal_risk:
                risk_factors.append(temporal_risk)
            
            # 5. Device and behavioral analysis
            device_risk = await self._analyze_device_risk(transaction_data, user_id)
            if device_risk:
                risk_factors.append(device_risk)
            
            # 6. Apply fraud rules
            rule_results = await self._apply_fraud_rules(transaction_data)
            risk_factors.extend(rule_results['risk_factors'])
            triggered_rules.extend(rule_results['triggered_rules'])
            
            # Calculate total risk score
            total_risk_score = self._calculate_total_risk_score(risk_factors)
            
            # Determine risk level
            risk_level = self._determine_risk_level(total_risk_score)
            
            # Generate recommendations
            recommendations = self._generate_recommendations(risk_factors, total_risk_score)
            
            # Determine if manual review is required
            requires_manual_review = (
                total_risk_score >= settings.default_risk_threshold or
                any(rf.severity == 'high' for rf in risk_factors) or
                len(triggered_rules) >= 2
            )
            
            # Update transaction cache
            self._update_transaction_cache(user_id, transaction_data)
            
            return FraudAssessment(
                transaction_id=transaction_id,
                total_risk_score=total_risk_score,
                risk_level=risk_level,
                risk_factors=risk_factors,
                triggered_rules=triggered_rules,
                recommendations=recommendations,
                requires_manual_review=requires_manual_review
            )
            
        except Exception as e:
            logger.error(f"❌ Error analyzing transaction {transaction_data.get('id')}: {e}")
            # Return safe default assessment
            return FraudAssessment(
                transaction_id=transaction_data.get('id', 0),
                total_risk_score=0.0,
                risk_level='low',
                risk_factors=[],
                triggered_rules=[],
                recommendations=['Error in analysis - manual review recommended'],
                requires_manual_review=True
            )
    
    async def _analyze_amount_risk(self, amount: float, user_id: int) -> Optional[RiskFactor]:
        """Analyze transaction amount for risk factors"""
        try:
            # Get user's transaction history for comparison
            user_transactions = list(self.transaction_cache.get(user_id, []))
            
            if not user_transactions:
                # New user - higher risk for large amounts
                if amount > 1000:
                    return RiskFactor(
                        name="High Amount - New User",
                        score=min(amount / 1000 * 20, 40),
                        description=f"Large transaction (${amount:,.2f}) from new user",
                        severity="medium" if amount < 5000 else "high"
                    )
                return None
            
            # Calculate user's average transaction amount
            avg_amount = sum(t['amount'] for t in user_transactions) / len(user_transactions)
            
            # Check for amount anomalies
            if amount > avg_amount * 5:  # 5x average
                return RiskFactor(
                    name="Amount Anomaly",
                    score=min((amount / avg_amount) * 5, 35),
                    description=f"Transaction amount (${amount:,.2f}) is {amount/avg_amount:.1f}x user's average",
                    severity="high" if amount > avg_amount * 10 else "medium"
                )
            
            # Check absolute thresholds
            if amount > settings.max_transaction_amount:
                return RiskFactor(
                    name="High Value Transaction",
                    score=40,
                    description=f"Transaction exceeds maximum threshold (${settings.max_transaction_amount:,.2f})",
                    severity="high"
                )
            
            return None
            
        except Exception as e:
            logger.error(f"Error in amount risk analysis: {e}")
            return None
    
    async def _analyze_velocity_risk(self, user_id: int, timestamp: datetime) -> Optional[RiskFactor]:
        """Analyze transaction velocity for risk factors"""
        try:
            # Get recent transactions for this user
            user_transactions = list(self.transaction_cache.get(user_id, []))
            
            if not user_transactions:
                return None
            
            # Count transactions in the last hour
            one_hour_ago = timestamp - timedelta(hours=1)
            recent_count = sum(1 for t in user_transactions if t['timestamp'] >= one_hour_ago)
            
            # Velocity thresholds
            if recent_count >= 10:
                return RiskFactor(
                    name="High Velocity",
                    score=30 + (recent_count - 10) * 3,
                    description=f"{recent_count} transactions in the last hour",
                    severity="high"
                )
            elif recent_count >= 5:
                return RiskFactor(
                    name="Moderate Velocity",
                    score=15 + (recent_count - 5) * 2,
                    description=f"{recent_count} transactions in the last hour",
                    severity="medium"
                )
            
            # Check for rapid-fire transactions (within minutes)
            if len(user_transactions) >= 2:
                last_transaction = max(user_transactions, key=lambda t: t['timestamp'])
                time_diff = (timestamp - last_transaction['timestamp']).total_seconds()
                
                if time_diff < 60:  # Less than 1 minute
                    return RiskFactor(
                        name="Rapid Transactions",
                        score=25,
                        description=f"Transaction within {time_diff:.0f} seconds of previous",
                        severity="medium"
                    )
            
            return None
            
        except Exception as e:
            logger.error(f"Error in velocity risk analysis: {e}")
            return None
    
    async def _analyze_geographic_risk(self, transaction_data: Dict[str, Any]) -> Optional[RiskFactor]:
        """Analyze geographic risk factors"""
        try:
            country_code = transaction_data.get('country_code', 'US')
            location = transaction_data.get('location', '')
            user_id = transaction_data.get('user_id')
            
            # Check country risk score
            country_risk = self.country_risk_scores.get(country_code, 0.3)
            
            if country_risk > 0.5:
                return RiskFactor(
                    name="High Risk Country",
                    score=country_risk * 40,
                    description=f"Transaction from high-risk country: {country_code}",
                    severity="high" if country_risk > 0.8 else "medium"
                )
            
            # Check for geographic anomalies
            user_transactions = list(self.transaction_cache.get(user_id, []))
            if user_transactions:
                # Get user's typical countries
                user_countries = [t.get('country_code', 'US') for t in user_transactions[-10:]]
                most_common_country = max(set(user_countries), key=user_countries.count)
                
                if country_code != most_common_country and country_code not in user_countries:
                    return RiskFactor(
                        name="Geographic Anomaly",
                        score=20,
                        description=f"Transaction from unusual country: {country_code}",
                        severity="medium"
                    )
            
            return None
            
        except Exception as e:
            logger.error(f"Error in geographic risk analysis: {e}")
            return None
    
    async def _analyze_temporal_risk(self, timestamp: datetime, user_id: int) -> Optional[RiskFactor]:
        """Analyze temporal patterns for risk factors"""
        try:
            hour = timestamp.hour
            day_of_week = timestamp.weekday()  # 0=Monday, 6=Sunday
            
            # Off-hours risk (11 PM - 6 AM)
            if hour >= 23 or hour <= 6:
                return RiskFactor(
                    name="Off-Hours Transaction",
                    score=15,
                    description=f"Transaction at {timestamp.strftime('%H:%M')} (off-hours)",
                    severity="low"
                )
            
            # Weekend risk for business transactions
            if day_of_week >= 5:  # Saturday or Sunday
                return RiskFactor(
                    name="Weekend Transaction",
                    score=10,
                    description=f"Transaction on {timestamp.strftime('%A')}",
                    severity="low"
                )
            
            return None
            
        except Exception as e:
            logger.error(f"Error in temporal risk analysis: {e}")
            return None
    
    async def _analyze_device_risk(self, transaction_data: Dict[str, Any], user_id: int) -> Optional[RiskFactor]:
        """Analyze device and behavioral risk factors"""
        try:
            device_id = transaction_data.get('device_id', '')
            ip_address = transaction_data.get('ip_address', '')
            
            # Get user's device history
            user_transactions = list(self.transaction_cache.get(user_id, []))
            
            if user_transactions:
                # Check for new device
                user_devices = [t.get('device_id', '') for t in user_transactions[-20:]]
                if device_id and device_id not in user_devices:
                    return RiskFactor(
                        name="New Device",
                        score=20,
                        description=f"Transaction from new device: {device_id[:10]}...",
                        severity="medium"
                    )
                
                # Check for IP address changes (simplified)
                user_ips = [t.get('ip_address', '') for t in user_transactions[-10:]]
                if ip_address and ip_address not in user_ips:
                    return RiskFactor(
                        name="New IP Address",
                        score=15,
                        description=f"Transaction from new IP address",
                        severity="low"
                    )
            
            return None
            
        except Exception as e:
            logger.error(f"Error in device risk analysis: {e}")
            return None
    
    async def _apply_fraud_rules(self, transaction_data: Dict[str, Any]) -> Dict[str, List]:
        """Apply configured fraud detection rules"""
        risk_factors = []
        triggered_rules = []
        
        try:
            for rule in self.active_rules:
                if await self._evaluate_rule(rule, transaction_data):
                    triggered_rules.append(rule['id'])
                    
                    # Create risk factor for triggered rule
                    severity = "high" if rule['priority'] == 1 else "medium" if rule['priority'] == 2 else "low"
                    score = 30 if rule['priority'] == 1 else 20 if rule['priority'] == 2 else 10
                    
                    risk_factors.append(RiskFactor(
                        name=f"Rule: {rule['name']}",
                        score=score,
                        description=f"Triggered fraud rule: {rule['name']}",
                        severity=severity
                    ))
                    
                    # Update rule statistics
                    await self._update_rule_stats(rule['id'])
            
            return {
                'risk_factors': risk_factors,
                'triggered_rules': triggered_rules
            }
            
        except Exception as e:
            logger.error(f"Error applying fraud rules: {e}")
            return {'risk_factors': [], 'triggered_rules': []}
    
    async def _evaluate_rule(self, rule: Dict[str, Any], transaction_data: Dict[str, Any]) -> bool:
        """Evaluate a single fraud rule against transaction data"""
        try:
            rule_type = rule['rule_type']
            conditions = rule['conditions']
            threshold = rule['threshold']
            
            if rule_type == 'amount_threshold':
                amount = transaction_data.get('amount', 0)
                operator = conditions.get('amount', {}).get('operator', '>')
                value = conditions.get('amount', {}).get('value', threshold)
                
                if operator == '>':
                    return amount > value
                elif operator == '>=':
                    return amount >= value
                elif operator == '<':
                    return amount < value
                elif operator == '<=':
                    return amount <= value
                elif operator == '==':
                    return amount == value
            
            elif rule_type == 'velocity_check':
                user_id = transaction_data.get('user_id')
                timestamp = transaction_data.get('timestamp', datetime.now())
                window_minutes = conditions.get('window_minutes', 60)
                max_count = conditions.get('count', {}).get('value', threshold)
                
                # Count transactions in the time window
                cutoff_time = timestamp - timedelta(minutes=window_minutes)
                user_transactions = self.transaction_cache.get(user_id, [])
                recent_count = sum(1 for t in user_transactions if t['timestamp'] >= cutoff_time)
                
                return recent_count > max_count
            
            elif rule_type == 'geographic':
                country_code = transaction_data.get('country_code', 'US')
                risk_countries = conditions.get('countries', [])
                return country_code in risk_countries
            
            elif rule_type == 'time_based':
                timestamp = transaction_data.get('timestamp', datetime.now())
                hour = timestamp.hour
                start_hour = conditions.get('hours', {}).get('start', 23)
                end_hour = conditions.get('hours', {}).get('end', 6)
                
                if start_hour > end_hour:  # Overnight period
                    return hour >= start_hour or hour <= end_hour
                else:
                    return start_hour <= hour <= end_hour
            
            return False
            
        except Exception as e:
            logger.error(f"Error evaluating rule {rule.get('name', 'unknown')}: {e}")
            return False
    
    async def _update_rule_stats(self, rule_id: int):
        """Update rule trigger statistics"""
        try:
            db = SessionLocal()
            rule = db.query(FraudRule).filter(FraudRule.id == rule_id).first()
            if rule:
                rule.total_triggers += 1
                rule.last_triggered = datetime.now()
                db.commit()
            db.close()
        except Exception as e:
            logger.error(f"Error updating rule stats: {e}")
    
    def _calculate_total_risk_score(self, risk_factors: List[RiskFactor]) -> float:
        """Calculate total risk score from individual risk factors"""
        if not risk_factors:
            return 0.0
        
        # Use weighted scoring with diminishing returns
        total_score = 0.0
        severity_multipliers = {'low': 0.5, 'medium': 1.0, 'high': 1.5}
        
        for factor in risk_factors:
            multiplier = severity_multipliers.get(factor.severity, 1.0)
            total_score += factor.score * multiplier
        
        # Apply diminishing returns to prevent score inflation
        if total_score > 100:
            total_score = 100 - (100 - total_score) * 0.1
        
        return min(total_score, 100.0)
    
    def _determine_risk_level(self, risk_score: float) -> str:
        """Determine risk level based on total risk score"""
        if risk_score >= 70:
            return 'high'
        elif risk_score >= 40:
            return 'medium'
        else:
            return 'low'
    
    def _generate_recommendations(self, risk_factors: List[RiskFactor], risk_score: float) -> List[str]:
        """Generate actionable recommendations based on risk assessment"""
        recommendations = []
        
        if risk_score >= 80:
            recommendations.append("🚨 IMMEDIATE ACTION: Block transaction and investigate")
            recommendations.append("📞 Contact customer to verify transaction")
        elif risk_score >= 60:
            recommendations.append("⚠️ Hold transaction for manual review")
            recommendations.append("🔍 Investigate user's recent activity pattern")
        elif risk_score >= 40:
            recommendations.append("👁️ Monitor user for additional suspicious activity")
            recommendations.append("📊 Review transaction against user's historical patterns")
        else:
            recommendations.append("✅ Transaction appears normal - continue monitoring")
        
        # Add specific recommendations based on risk factors
        factor_names = [rf.name for rf in risk_factors]
        
        if any('Velocity' in name for name in factor_names):
            recommendations.append("🏃 Implement velocity controls for this user")
        
        if any('Geographic' in name for name in factor_names):
            recommendations.append("🌍 Verify user's current location")
        
        if any('Device' in name for name in factor_names):
            recommendations.append("📱 Implement additional device authentication")
        
        if any('Amount' in name for name in factor_names):
            recommendations.append("💰 Verify source of funds for large transactions")
        
        return recommendations
    
    def _update_transaction_cache(self, user_id: int, transaction_data: Dict[str, Any]):
        """Update transaction cache with new transaction"""
        try:
            cache_entry = {
                'id': transaction_data.get('id'),
                'amount': transaction_data.get('amount'),
                'timestamp': transaction_data.get('timestamp', datetime.now()),
                'location': transaction_data.get('location'),
                'country_code': transaction_data.get('country_code'),
                'device_id': transaction_data.get('device_id')
            }
            
            # Add to cache
            self.transaction_cache[user_id].append(cache_entry)
            
            # Keep only recent transactions (last 100 per user)
            if len(self.transaction_cache[user_id]) > 100:
                self.transaction_cache[user_id].popleft()
                
        except Exception as e:
            logger.error(f"Error updating transaction cache: {e}")
    
    async def create_alert_if_needed(self, assessment: FraudAssessment) -> Optional[int]:
        """Create fraud alert if assessment indicates high risk"""
        if not assessment.requires_manual_review:
            return None
        
        try:
            db = SessionLocal()
            
            # Determine alert severity
            if assessment.total_risk_score >= 80:
                severity = 'high'
            elif assessment.total_risk_score >= 50:
                severity = 'medium'
            else:
                severity = 'low'
            
            # Create alert
            alert = Alert(
                transaction_id=assessment.transaction_id,
                rule_id=assessment.triggered_rules[0] if assessment.triggered_rules else None,
                title=f"Fraud Alert - Risk Score {assessment.total_risk_score:.1f}",
                description=f"Automated fraud detection triggered. Risk factors: {', '.join([rf.name for rf in assessment.risk_factors])}",
                severity=severity,
                risk_score=assessment.total_risk_score,
                status='open'
            )
            
            db.add(alert)
            db.commit()
            alert_id = alert.id
            db.close()
            
            logger.info(f"🚨 Created fraud alert {alert_id} for transaction {assessment.transaction_id}")
            return alert_id
            
        except Exception as e:
            logger.error(f"Error creating fraud alert: {e}")
            return None