"""
Fraud Detection Service - Core business logic for fraud analysis and management
Handles transaction analysis, rule management, and fraud metrics
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import func, and_, or_, desc

from ..core.database import SessionLocal, Transaction, FraudRule, Alert, User
from ..core.fraud_engine import FraudDetectionEngine, FraudAssessment
from ..core.config import settings

logger = logging.getLogger(__name__)

class FraudDetectionService:
    """Service for fraud detection operations and analytics"""
    
    def __init__(self, fraud_engine: FraudDetectionEngine):
        self.fraud_engine = fraud_engine
        self.cache = {}
        self.cache_ttl = 300  # 5 minutes
        logger.info("🔍 Fraud Detection Service initialized")
    
    async def analyze_transaction(self, transaction_data: Dict[str, Any]) -> FraudAssessment:
        """Analyze a transaction for fraud indicators"""
        try:
            # Use the fraud engine for analysis
            assessment = await self.fraud_engine.analyze_transaction(transaction_data)
            
            # Update transaction in database with risk score
            await self._update_transaction_risk_score(
                transaction_data['id'], 
                assessment.total_risk_score,
                assessment.risk_level
            )
            
            # Create alert if needed
            if assessment.requires_manual_review:
                alert_id = await self.fraud_engine.create_alert_if_needed(assessment)
                if alert_id:
                    logger.info(f"🚨 Created alert {alert_id} for transaction {transaction_data['id']}")
            
            return assessment
            
        except Exception as e:
            logger.error(f"Error analyzing transaction: {e}")
            raise
    
    async def get_dashboard_metrics(self) -> Dict[str, Any]:
        """Get real-time dashboard metrics"""
        cache_key = "dashboard_metrics"
        
        # Check cache
        if self._is_cache_valid(cache_key):
            return self.cache[cache_key]['data']
        
        try:
            db = SessionLocal()
            
            # Calculate date ranges
            now = datetime.now()
            today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
            yesterday_start = today_start - timedelta(days=1)
            week_start = today_start - timedelta(days=7)
            
            # Total transactions (last 24 hours)
            total_transactions = db.query(Transaction).filter(
                Transaction.timestamp >= yesterday_start
            ).count()
            
            # Active alerts
            active_alerts = db.query(Alert).filter(
                Alert.status.in_(['open', 'in_progress'])
            ).count()
            
            # Average risk score (last 24 hours)
            avg_risk_result = db.query(func.avg(Transaction.risk_score)).filter(
                and_(
                    Transaction.timestamp >= yesterday_start,
                    Transaction.risk_score > 0
                )
            ).scalar()
            avg_risk_score = float(avg_risk_result) if avg_risk_result else 0.0
            
            # Open cases (from case management service)
            # For now, we'll use a placeholder
            open_cases = 0  # This would be implemented with case management
            
            metrics = {
                'total_transactions': total_transactions,
                'active_alerts': active_alerts,
                'avg_risk_score': avg_risk_score,
                'open_cases': open_cases,
                'last_updated': now.isoformat()
            }
            
            # Cache the results
            self._cache_data(cache_key, metrics)
            
            db.close()
            return metrics
            
        except Exception as e:
            logger.error(f"Error getting dashboard metrics: {e}")
            return {
                'total_transactions': 0,
                'active_alerts': 0,
                'avg_risk_score': 0.0,
                'open_cases': 0,
                'last_updated': datetime.now().isoformat()
            }
    
    async def get_fraud_trends(self, days: int = 30) -> Dict[str, List]:
        """Get fraud detection trends over time"""
        cache_key = f"fraud_trends_{days}"
        
        if self._is_cache_valid(cache_key):
            return self.cache[cache_key]['data']
        
        try:
            db = SessionLocal()
            
            # Calculate date range
            end_date = datetime.now().date()
            start_date = end_date - timedelta(days=days)
            
            # Get daily fraud counts
            fraud_counts = db.query(
                func.date(Alert.created_at).label('date'),
                func.count(Alert.id).label('count')
            ).filter(
                and_(
                    Alert.created_at >= start_date,
                    Alert.severity.in_(['high', 'medium'])
                )
            ).group_by(
                func.date(Alert.created_at)
            ).order_by('date').all()
            
            # Fill in missing dates with zero counts
            dates = []
            fraud_count = []
            
            current_date = start_date
            fraud_dict = {str(row.date): row.count for row in fraud_counts}
            
            while current_date <= end_date:
                dates.append(current_date.strftime('%Y-%m-%d'))
                fraud_count.append(fraud_dict.get(str(current_date), 0))
                current_date += timedelta(days=1)
            
            trends = {
                'dates': dates,
                'fraud_count': fraud_count
            }
            
            self._cache_data(cache_key, trends)
            db.close()
            return trends
            
        except Exception as e:
            logger.error(f"Error getting fraud trends: {e}")
            return {'dates': [], 'fraud_count': []}
    
    async def get_risk_distribution(self) -> Dict[str, List]:
        """Get risk score distribution"""
        cache_key = "risk_distribution"
        
        if self._is_cache_valid(cache_key):
            return self.cache[cache_key]['data']
        
        try:
            db = SessionLocal()
            
            # Get risk score distribution for last 7 days
            week_ago = datetime.now() - timedelta(days=7)
            
            # Count transactions by risk level
            low_risk = db.query(Transaction).filter(
                and_(
                    Transaction.timestamp >= week_ago,
                    Transaction.risk_score < 40
                )
            ).count()
            
            medium_risk = db.query(Transaction).filter(
                and_(
                    Transaction.timestamp >= week_ago,
                    Transaction.risk_score >= 40,
                    Transaction.risk_score < 70
                )
            ).count()
            
            high_risk = db.query(Transaction).filter(
                and_(
                    Transaction.timestamp >= week_ago,
                    Transaction.risk_score >= 70
                )
            ).count()
            
            distribution = {
                'risk_ranges': ['Low (0-39)', 'Medium (40-69)', 'High (70-100)'],
                'counts': [low_risk, medium_risk, high_risk]
            }
            
            self._cache_data(cache_key, distribution)
            db.close()
            return distribution
            
        except Exception as e:
            logger.error(f"Error getting risk distribution: {e}")
            return {'risk_ranges': [], 'counts': []}
    
    async def get_suspicious_transactions(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent suspicious transactions"""
        try:
            db = SessionLocal()
            
            transactions = db.query(Transaction).filter(
                or_(
                    Transaction.is_suspicious == True,
                    Transaction.risk_score >= 50
                )
            ).order_by(desc(Transaction.timestamp)).limit(limit).all()
            
            result = []
            for transaction in transactions:
                result.append({
                    'id': transaction.id,
                    'user_id': transaction.user_id,
                    'amount': transaction.amount,
                    'type': transaction.transaction_type,
                    'risk_score': transaction.risk_score,
                    'status': transaction.status,
                    'timestamp': transaction.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                    'location': transaction.location,
                    'country_code': transaction.country_code
                })
            
            db.close()
            return result
            
        except Exception as e:
            logger.error(f"Error getting suspicious transactions: {e}")
            return []
    
    async def get_filtered_transactions(self, filters: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Get transactions with applied filters"""
        try:
            db = SessionLocal()
            
            query = db.query(Transaction)
            
            # Apply filters
            if filters.get('date_from'):
                query = query.filter(Transaction.timestamp >= filters['date_from'])
            
            if filters.get('date_to'):
                query = query.filter(Transaction.timestamp <= filters['date_to'])
            
            if filters.get('min_amount'):
                query = query.filter(Transaction.amount >= filters['min_amount'])
            
            if filters.get('max_amount'):
                query = query.filter(Transaction.amount <= filters['max_amount'])
            
            if filters.get('min_risk_score'):
                query = query.filter(Transaction.risk_score >= filters['min_risk_score'])
            
            if filters.get('status'):
                query = query.filter(Transaction.status == filters['status'])
            
            # Order by timestamp descending and limit results
            transactions = query.order_by(desc(Transaction.timestamp)).limit(100).all()
            
            result = []
            for transaction in transactions:
                result.append({
                    'id': transaction.id,
                    'user_id': transaction.user_id,
                    'amount': transaction.amount,
                    'type': transaction.transaction_type,
                    'risk_score': transaction.risk_score,
                    'status': transaction.status,
                    'timestamp': transaction.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                    'location': transaction.location,
                    'country_code': transaction.country_code,
                    'merchant': transaction.merchant,
                    'device_id': transaction.device_id
                })
            
            db.close()
            return result
            
        except Exception as e:
            logger.error(f"Error getting filtered transactions: {e}")
            return []
    
    async def get_transaction_by_id(self, transaction_id: int) -> Optional[Dict[str, Any]]:
        """Get transaction details by ID"""
        try:
            db = SessionLocal()
            
            transaction = db.query(Transaction).filter(Transaction.id == transaction_id).first()
            
            if not transaction:
                db.close()
                return None
            
            result = {
                'id': transaction.id,
                'user_id': transaction.user_id,
                'amount': transaction.amount,
                'type': transaction.transaction_type,
                'risk_score': transaction.risk_score,
                'status': transaction.status,
                'timestamp': transaction.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                'location': transaction.location,
                'country_code': transaction.country_code,
                'merchant': transaction.merchant,
                'device_id': transaction.device_id,
                'ip_address': transaction.ip_address,
                'raw_data': transaction.raw_data
            }
            
            db.close()
            return result
            
        except Exception as e:
            logger.error(f"Error getting transaction {transaction_id}: {e}")
            return None
    
    async def get_transaction_risk_factors(self, transaction_id: int) -> List[str]:
        """Get risk factors for a specific transaction"""
        try:
            # This would typically involve re-analyzing the transaction
            # For now, we'll return some example risk factors
            transaction = await self.get_transaction_by_id(transaction_id)
            
            if not transaction:
                return []
            
            risk_factors = []
            
            if transaction['risk_score'] > 70:
                risk_factors.append("High risk score detected")
            
            if transaction['amount'] > 10000:
                risk_factors.append("Large transaction amount")
            
            if transaction['country_code'] in ['XX', 'YY', 'ZZ']:
                risk_factors.append("Transaction from high-risk country")
            
            if 'off_hours' in str(transaction.get('raw_data', {})):
                risk_factors.append("Transaction during off-hours")
            
            return risk_factors
            
        except Exception as e:
            logger.error(f"Error getting risk factors for transaction {transaction_id}: {e}")
            return []
    
    async def flag_transaction(self, transaction_id: int) -> bool:
        """Flag a transaction as suspicious"""
        try:
            db = SessionLocal()
            
            transaction = db.query(Transaction).filter(Transaction.id == transaction_id).first()
            
            if not transaction:
                db.close()
                return False
            
            transaction.status = 'flagged'
            transaction.is_suspicious = True
            transaction.updated_at = datetime.now()
            
            db.commit()
            db.close()
            
            logger.info(f"🚩 Transaction {transaction_id} flagged as suspicious")
            return True
            
        except Exception as e:
            logger.error(f"Error flagging transaction {transaction_id}: {e}")
            return False
    
    async def get_fraud_rules(self) -> List[Dict[str, Any]]:
        """Get all fraud detection rules"""
        try:
            db = SessionLocal()
            
            rules = db.query(FraudRule).order_by(FraudRule.priority, FraudRule.name).all()
            
            result = []
            for rule in rules:
                # Calculate accuracy
                accuracy = 0.0
                if rule.total_triggers > 0:
                    accuracy = (rule.true_positives / rule.total_triggers) * 100
                
                result.append({
                    'id': rule.id,
                    'name': rule.name,
                    'type': rule.rule_type,
                    'threshold': rule.threshold,
                    'active': rule.is_active,
                    'accuracy': accuracy,
                    'total_triggers': rule.total_triggers,
                    'true_positives': rule.true_positives,
                    'false_positives': rule.false_positives,
                    'created_at': rule.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                    'last_triggered': rule.last_triggered.strftime('%Y-%m-%d %H:%M:%S') if rule.last_triggered else None,
                    'description': rule.description
                })
            
            db.close()
            return result
            
        except Exception as e:
            logger.error(f"Error getting fraud rules: {e}")
            return []
    
    async def get_rules_summary(self) -> Dict[str, Any]:
        """Get fraud rules summary statistics"""
        try:
            db = SessionLocal()
            
            active_rules = db.query(FraudRule).filter(FraudRule.is_active == True).count()
            inactive_rules = db.query(FraudRule).filter(FraudRule.is_active == False).count()
            
            # Triggered today
            today_start = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
            triggered_today = db.query(FraudRule).filter(
                FraudRule.last_triggered >= today_start
            ).count()
            
            # Average accuracy
            avg_accuracy_result = db.query(func.avg(
                func.case(
                    [(FraudRule.total_triggers > 0, 
                      (FraudRule.true_positives * 100.0) / FraudRule.total_triggers)],
                    else_=0
                )
            )).scalar()
            
            avg_accuracy = float(avg_accuracy_result) if avg_accuracy_result else 0.0
            
            summary = {
                'active': active_rules,
                'inactive': inactive_rules,
                'triggered_today': triggered_today,
                'avg_accuracy': avg_accuracy
            }
            
            db.close()
            return summary
            
        except Exception as e:
            logger.error(f"Error getting rules summary: {e}")
            return {'active': 0, 'inactive': 0, 'triggered_today': 0, 'avg_accuracy': 0.0}
    
    async def create_fraud_rule(self, rule_data: Dict[str, Any]) -> int:
        """Create a new fraud detection rule"""
        try:
            db = SessionLocal()
            
            rule = FraudRule(
                name=rule_data['name'],
                rule_type=rule_data['type'],
                conditions={'threshold': rule_data['threshold']},  # Simplified for demo
                threshold=rule_data['threshold'],
                is_active=rule_data.get('active', True),
                description=rule_data.get('description', ''),
                priority=1  # Default priority
            )
            
            db.add(rule)
            db.commit()
            rule_id = rule.id
            db.close()
            
            # Reload active rules in fraud engine
            await self.fraud_engine.load_active_rules()
            
            logger.info(f"✅ Created fraud rule {rule_id}: {rule_data['name']}")
            return rule_id
            
        except Exception as e:
            logger.error(f"Error creating fraud rule: {e}")
            raise
    
    async def update_fraud_rule(self, rule_id: int, updates: Dict[str, Any]) -> bool:
        """Update an existing fraud rule"""
        try:
            db = SessionLocal()
            
            rule = db.query(FraudRule).filter(FraudRule.id == rule_id).first()
            
            if not rule:
                db.close()
                return False
            
            # Update fields
            if 'name' in updates:
                rule.name = updates['name']
            if 'type' in updates:
                rule.rule_type = updates['type']
            if 'threshold' in updates:
                rule.threshold = updates['threshold']
                rule.conditions = {'threshold': updates['threshold']}  # Simplified
            if 'active' in updates:
                rule.is_active = updates['active']
            if 'description' in updates:
                rule.description = updates['description']
            
            rule.updated_at = datetime.now()
            
            db.commit()
            db.close()
            
            # Reload active rules in fraud engine
            await self.fraud_engine.load_active_rules()
            
            logger.info(f"✅ Updated fraud rule {rule_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error updating fraud rule {rule_id}: {e}")
            return False
    
    async def get_rule_metrics(self, rule_id: int) -> Dict[str, Any]:
        """Get performance metrics for a specific rule"""
        try:
            db = SessionLocal()
            
            rule = db.query(FraudRule).filter(FraudRule.id == rule_id).first()
            
            if not rule:
                db.close()
                return {}
            
            # Calculate metrics
            precision = 0.0
            recall = 0.0
            
            if rule.total_triggers > 0:
                precision = (rule.true_positives / rule.total_triggers) * 100
            
            # Recall calculation would require more complex analysis
            # For now, we'll use a simplified calculation
            recall = precision * 0.8  # Simplified assumption
            
            metrics = {
                'total_triggers': rule.total_triggers,
                'true_positives': rule.true_positives,
                'false_positives': rule.false_positives,
                'precision': precision,
                'recall': recall
            }
            
            db.close()
            return metrics
            
        except Exception as e:
            logger.error(f"Error getting rule metrics for {rule_id}: {e}")
            return {}
    
    async def load_default_rules(self):
        """Load default fraud detection rules if none exist"""
        try:
            db = SessionLocal()
            
            # Check if rules already exist
            existing_rules = db.query(FraudRule).count()
            
            if existing_rules > 0:
                db.close()
                logger.info("📋 Fraud rules already exist, skipping default rule creation")
                return
            
            # Create default rules (these are already created in database initialization)
            logger.info("📋 Default fraud rules loaded from database initialization")
            db.close()
            
        except Exception as e:
            logger.error(f"Error loading default rules: {e}")
    
    async def _update_transaction_risk_score(self, transaction_id: int, risk_score: float, risk_level: str):
        """Update transaction with calculated risk score"""
        try:
            db = SessionLocal()
            
            transaction = db.query(Transaction).filter(Transaction.id == transaction_id).first()
            
            if transaction:
                transaction.risk_score = risk_score
                transaction.is_suspicious = risk_score >= settings.default_risk_threshold
                transaction.status = 'flagged' if risk_score >= 80 else 'normal'
                transaction.updated_at = datetime.now()
                
                db.commit()
            
            db.close()
            
        except Exception as e:
            logger.error(f"Error updating transaction risk score: {e}")
    
    def _is_cache_valid(self, key: str) -> bool:
        """Check if cached data is still valid"""
        if key not in self.cache:
            return False
        
        cache_time = self.cache[key]['timestamp']
        return (datetime.now() - cache_time).total_seconds() < self.cache_ttl
    
    def _cache_data(self, key: str, data: Any):
        """Cache data with timestamp"""
        self.cache[key] = {
            'data': data,
            'timestamp': datetime.now()
        }