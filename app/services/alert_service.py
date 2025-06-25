"""
Alert Service - Manages fraud alerts, notifications, and alert lifecycle
Handles alert creation, assignment, resolution, and reporting
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from sqlalchemy.orm import Session
from sqlalchemy import func, and_, or_, desc

from ..core.database import SessionLocal, Alert, Transaction, FraudRule, User
from ..core.config import settings

logger = logging.getLogger(__name__)

class AlertService:
    """Service for managing fraud alerts and notifications"""
    
    def __init__(self):
        self.cache = {}
        self.cache_ttl = 180  # 3 minutes
        logger.info("🚨 Alert Service initialized")
    
    async def get_recent_alerts(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent high-priority alerts"""
        try:
            db = SessionLocal()
            
            alerts = db.query(Alert).filter(
                Alert.status.in_(['open', 'in_progress'])
            ).order_by(desc(Alert.created_at)).limit(limit).all()
            
            result = []
            for alert in alerts:
                result.append({
                    'id': alert.id,
                    'title': alert.title,
                    'severity': alert.severity,
                    'risk_score': alert.risk_score,
                    'status': alert.status,
                    'created_at': alert.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                    'transaction_id': alert.transaction_id
                })
            
            db.close()
            return result
            
        except Exception as e:
            logger.error(f"Error getting recent alerts: {e}")
            return []
    
    async def get_filtered_alerts(self, filters: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Get alerts with applied filters"""
        try:
            db = SessionLocal()
            
            query = db.query(Alert)
            
            # Apply filters
            if filters.get('severity'):
                query = query.filter(Alert.severity == filters['severity'].lower())
            
            if filters.get('status'):
                query = query.filter(Alert.status == filters['status'].lower().replace(' ', '_'))
            
            if filters.get('date_from'):
                query = query.filter(Alert.created_at >= filters['date_from'])
            
            if filters.get('date_to'):
                query = query.filter(Alert.created_at <= filters['date_to'])
            
            if filters.get('assigned_to'):
                query = query.filter(Alert.assigned_to == filters['assigned_to'])
            
            # Order by creation date descending
            alerts = query.order_by(desc(Alert.created_at)).limit(100).all()
            
            result = []
            for alert in alerts:
                result.append({
                    'id': alert.id,
                    'title': alert.title,
                    'description': alert.description,
                    'severity': alert.severity,
                    'risk_score': alert.risk_score,
                    'status': alert.status,
                    'created_at': alert.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                    'updated_at': alert.updated_at.strftime('%Y-%m-%d %H:%M:%S') if alert.updated_at else None,
                    'resolved_at': alert.resolved_at.strftime('%Y-%m-%d %H:%M:%S') if alert.resolved_at else None,
                    'transaction_id': alert.transaction_id,
                    'rule_id': alert.rule_id,
                    'assigned_to': alert.assigned_to,
                    'resolution_notes': alert.resolution_notes
                })
            
            db.close()
            return result
            
        except Exception as e:
            logger.error(f"Error getting filtered alerts: {e}")
            return []
    
    async def get_alert_summary(self) -> Dict[str, Any]:
        """Get alert summary statistics"""
        cache_key = "alert_summary"
        
        if self._is_cache_valid(cache_key):
            return self.cache[cache_key]['data']
        
        try:
            db = SessionLocal()
            
            # Count alerts by severity
            high_alerts = db.query(Alert).filter(
                and_(Alert.severity == 'high', Alert.status.in_(['open', 'in_progress']))
            ).count()
            
            medium_alerts = db.query(Alert).filter(
                and_(Alert.severity == 'medium', Alert.status.in_(['open', 'in_progress']))
            ).count()
            
            low_alerts = db.query(Alert).filter(
                and_(Alert.severity == 'low', Alert.status.in_(['open', 'in_progress']))
            ).count()
            
            # Resolved today
            today_start = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
            resolved_today = db.query(Alert).filter(
                and_(
                    Alert.status == 'resolved',
                    Alert.resolved_at >= today_start
                )
            ).count()
            
            summary = {
                'high': high_alerts,
                'medium': medium_alerts,
                'low': low_alerts,
                'resolved_today': resolved_today,
                'total_active': high_alerts + medium_alerts + low_alerts
            }
            
            self._cache_data(cache_key, summary)
            db.close()
            return summary
            
        except Exception as e:
            logger.error(f"Error getting alert summary: {e}")
            return {'high': 0, 'medium': 0, 'low': 0, 'resolved_today': 0, 'total_active': 0}
    
    async def create_alert(self, alert_data: Dict[str, Any]) -> int:
        """Create a new fraud alert"""
        try:
            db = SessionLocal()
            
            alert = Alert(
                transaction_id=alert_data['transaction_id'],
                rule_id=alert_data.get('rule_id'),
                title=alert_data['title'],
                description=alert_data.get('description', ''),
                severity=alert_data['severity'],
                risk_score=alert_data['risk_score'],
                status='open',
                assigned_to=alert_data.get('assigned_to')
            )
            
            db.add(alert)
            db.commit()
            alert_id = alert.id
            db.close()
            
            logger.info(f"🚨 Created alert {alert_id}: {alert_data['title']}")
            
            # Send notification (placeholder for future implementation)
            await self._send_alert_notification(alert_id, alert_data)
            
            return alert_id
            
        except Exception as e:
            logger.error(f"Error creating alert: {e}")
            raise
    
    async def update_alert(self, alert_id: int, updates: Dict[str, Any]) -> bool:
        """Update an existing alert"""
        try:
            db = SessionLocal()
            
            alert = db.query(Alert).filter(Alert.id == alert_id).first()
            
            if not alert:
                db.close()
                return False
            
            # Update fields
            if 'status' in updates:
                alert.status = updates['status']
                if updates['status'] == 'resolved':
                    alert.resolved_at = datetime.now()
            
            if 'assigned_to' in updates:
                alert.assigned_to = updates['assigned_to']
            
            if 'resolution_notes' in updates:
                alert.resolution_notes = updates['resolution_notes']
            
            if 'severity' in updates:
                alert.severity = updates['severity']
            
            alert.updated_at = datetime.now()
            
            db.commit()
            db.close()
            
            logger.info(f"✅ Updated alert {alert_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error updating alert {alert_id}: {e}")
            return False
    
    async def resolve_alert(self, alert_id: int, resolution_notes: str = None) -> bool:
        """Resolve an alert"""
        try:
            updates = {
                'status': 'resolved',
                'resolution_notes': resolution_notes or 'Alert resolved'
            }
            
            success = await self.update_alert(alert_id, updates)
            
            if success:
                logger.info(f"✅ Resolved alert {alert_id}")
                
                # Update rule statistics if applicable
                await self._update_rule_statistics(alert_id, True)  # Assuming true positive
            
            return success
            
        except Exception as e:
            logger.error(f"Error resolving alert {alert_id}: {e}")
            return False
    
    async def assign_alert(self, alert_id: int, user_id: int) -> bool:
        """Assign an alert to a user"""
        try:
            updates = {
                'assigned_to': user_id,
                'status': 'in_progress'
            }
            
            success = await self.update_alert(alert_id, updates)
            
            if success:
                logger.info(f"👤 Assigned alert {alert_id} to user {user_id}")
            
            return success
            
        except Exception as e:
            logger.error(f"Error assigning alert {alert_id}: {e}")
            return False
    
    async def bulk_update_alerts(self, alert_ids: List[int], updates: Dict[str, Any]) -> int:
        """Update multiple alerts at once"""
        try:
            db = SessionLocal()
            
            # Update alerts
            updated_count = db.query(Alert).filter(
                Alert.id.in_(alert_ids)
            ).update(updates, synchronize_session=False)
            
            # Set updated_at timestamp
            db.query(Alert).filter(
                Alert.id.in_(alert_ids)
            ).update({'updated_at': datetime.now()}, synchronize_session=False)
            
            db.commit()
            db.close()
            
            logger.info(f"✅ Bulk updated {updated_count} alerts")
            return updated_count
            
        except Exception as e:
            logger.error(f"Error bulk updating alerts: {e}")
            return 0
    
    async def get_alert_details(self, alert_id: int) -> Optional[Dict[str, Any]]:
        """Get detailed information about a specific alert"""
        try:
            db = SessionLocal()
            
            alert = db.query(Alert).filter(Alert.id == alert_id).first()
            
            if not alert:
                db.close()
                return None
            
            # Get related transaction details
            transaction = db.query(Transaction).filter(Transaction.id == alert.transaction_id).first()
            
            # Get rule details if applicable
            rule = None
            if alert.rule_id:
                rule = db.query(FraudRule).filter(FraudRule.id == alert.rule_id).first()
            
            # Get assignee details if applicable
            assignee = None
            if alert.assigned_to:
                assignee = db.query(User).filter(User.id == alert.assigned_to).first()
            
            result = {
                'id': alert.id,
                'title': alert.title,
                'description': alert.description,
                'severity': alert.severity,
                'risk_score': alert.risk_score,
                'status': alert.status,
                'created_at': alert.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                'updated_at': alert.updated_at.strftime('%Y-%m-%d %H:%M:%S') if alert.updated_at else None,
                'resolved_at': alert.resolved_at.strftime('%Y-%m-%d %H:%M:%S') if alert.resolved_at else None,
                'resolution_notes': alert.resolution_notes,
                'transaction': {
                    'id': transaction.id,
                    'amount': transaction.amount,
                    'type': transaction.transaction_type,
                    'user_id': transaction.user_id,
                    'timestamp': transaction.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                    'location': transaction.location,
                    'country_code': transaction.country_code
                } if transaction else None,
                'rule': {
                    'id': rule.id,
                    'name': rule.name,
                    'type': rule.rule_type
                } if rule else None,
                'assignee': {
                    'id': assignee.id,
                    'username': assignee.username,
                    'full_name': assignee.full_name
                } if assignee else None
            }
            
            db.close()
            return result
            
        except Exception as e:
            logger.error(f"Error getting alert details for {alert_id}: {e}")
            return None
    
    async def get_alert_trends(self, days: int = 30) -> Dict[str, List]:
        """Get alert trends over time"""
        cache_key = f"alert_trends_{days}"
        
        if self._is_cache_valid(cache_key):
            return self.cache[cache_key]['data']
        
        try:
            db = SessionLocal()
            
            # Calculate date range
            end_date = datetime.now().date()
            start_date = end_date - timedelta(days=days)
            
            # Get daily alert counts by severity
            alert_counts = db.query(
                func.date(Alert.created_at).label('date'),
                Alert.severity,
                func.count(Alert.id).label('count')
            ).filter(
                Alert.created_at >= start_date
            ).group_by(
                func.date(Alert.created_at),
                Alert.severity
            ).order_by('date').all()
            
            # Organize data by date and severity
            dates = []
            high_counts = []
            medium_counts = []
            low_counts = []
            
            current_date = start_date
            alert_dict = {}
            
            # Organize alerts by date and severity
            for row in alert_counts:
                date_str = str(row.date)
                if date_str not in alert_dict:
                    alert_dict[date_str] = {'high': 0, 'medium': 0, 'low': 0}
                alert_dict[date_str][row.severity] = row.count
            
            # Fill in missing dates
            while current_date <= end_date:
                date_str = str(current_date)
                dates.append(current_date.strftime('%Y-%m-%d'))
                
                day_data = alert_dict.get(date_str, {'high': 0, 'medium': 0, 'low': 0})
                high_counts.append(day_data['high'])
                medium_counts.append(day_data['medium'])
                low_counts.append(day_data['low'])
                
                current_date += timedelta(days=1)
            
            trends = {
                'dates': dates,
                'high_alerts': high_counts,
                'medium_alerts': medium_counts,
                'low_alerts': low_counts
            }
            
            self._cache_data(cache_key, trends)
            db.close()
            return trends
            
        except Exception as e:
            logger.error(f"Error getting alert trends: {e}")
            return {'dates': [], 'high_alerts': [], 'medium_alerts': [], 'low_alerts': []}
    
    async def get_alert_performance_metrics(self) -> Dict[str, Any]:
        """Get alert performance and resolution metrics"""
        try:
            db = SessionLocal()
            
            # Calculate various metrics
            total_alerts = db.query(Alert).count()
            resolved_alerts = db.query(Alert).filter(Alert.status == 'resolved').count()
            
            # Average resolution time
            resolved_with_times = db.query(Alert).filter(
                and_(Alert.status == 'resolved', Alert.resolved_at.isnot(None))
            ).all()
            
            avg_resolution_hours = 0.0
            if resolved_with_times:
                total_hours = sum([
                    (alert.resolved_at - alert.created_at).total_seconds() / 3600
                    for alert in resolved_with_times
                ])
                avg_resolution_hours = total_hours / len(resolved_with_times)
            
            # False positive rate (simplified calculation)
            false_positives = db.query(Alert).filter(
                Alert.resolution_notes.like('%false positive%')
            ).count()
            
            false_positive_rate = 0.0
            if resolved_alerts > 0:
                false_positive_rate = (false_positives / resolved_alerts) * 100
            
            # Alerts by severity
            high_severity = db.query(Alert).filter(Alert.severity == 'high').count()
            medium_severity = db.query(Alert).filter(Alert.severity == 'medium').count()
            low_severity = db.query(Alert).filter(Alert.severity == 'low').count()
            
            metrics = {
                'total_alerts': total_alerts,
                'resolved_alerts': resolved_alerts,
                'resolution_rate': (resolved_alerts / total_alerts * 100) if total_alerts > 0 else 0,
                'avg_resolution_hours': avg_resolution_hours,
                'false_positive_rate': false_positive_rate,
                'severity_distribution': {
                    'high': high_severity,
                    'medium': medium_severity,
                    'low': low_severity
                }
            }
            
            db.close()
            return metrics
            
        except Exception as e:
            logger.error(f"Error getting alert performance metrics: {e}")
            return {}
    
    async def _send_alert_notification(self, alert_id: int, alert_data: Dict[str, Any]):
        """Send notification for new alert (placeholder for future implementation)"""
        try:
            # This would integrate with email, SMS, or other notification systems
            logger.info(f"📧 Notification sent for alert {alert_id} (placeholder)")
            
            # Future implementation could include:
            # - Email notifications to assigned users
            # - SMS alerts for high-severity incidents
            # - Slack/Teams integration
            # - Push notifications to mobile apps
            
        except Exception as e:
            logger.error(f"Error sending alert notification: {e}")
    
    async def _update_rule_statistics(self, alert_id: int, is_true_positive: bool):
        """Update fraud rule statistics based on alert resolution"""
        try:
            db = SessionLocal()
            
            alert = db.query(Alert).filter(Alert.id == alert_id).first()
            
            if alert and alert.rule_id:
                rule = db.query(FraudRule).filter(FraudRule.id == alert.rule_id).first()
                
                if rule:
                    if is_true_positive:
                        rule.true_positives += 1
                    else:
                        rule.false_positives += 1
                    
                    # Recalculate accuracy
                    if rule.total_triggers > 0:
                        rule.accuracy = (rule.true_positives / rule.total_triggers) * 100
                    
                    db.commit()
                    logger.info(f"📊 Updated statistics for rule {rule.id}")
            
            db.close()
            
        except Exception as e:
            logger.error(f"Error updating rule statistics: {e}")
    
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