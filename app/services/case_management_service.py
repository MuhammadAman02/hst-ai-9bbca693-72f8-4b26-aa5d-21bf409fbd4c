"""
Case Management Service - Handles fraud investigation cases and case lifecycle
Manages case creation, assignment, investigation notes, and case resolution
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from sqlalchemy.orm import Session
from sqlalchemy import func, and_, or_, desc

from ..core.database import SessionLocal, Case, Alert, CaseAlert, Investigation, User
from ..core.config import settings

logger = logging.getLogger(__name__)

class CaseManagementService:
    """Service for managing fraud investigation cases"""
    
    def __init__(self):
        self.cache = {}
        self.cache_ttl = 300  # 5 minutes
        logger.info("📋 Case Management Service initialized")
    
    async def get_filtered_cases(self, filters: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Get cases with applied filters"""
        try:
            db = SessionLocal()
            
            query = db.query(Case)
            
            # Apply filters
            if filters.get('status'):
                query = query.filter(Case.status == filters['status'].lower().replace(' ', '_'))
            
            if filters.get('priority'):
                query = query.filter(Case.priority == filters['priority'].lower())
            
            if filters.get('assignee'):
                # Join with User table to filter by username
                query = query.join(User, Case.assigned_to == User.id).filter(
                    User.username.like(f"%{filters['assignee']}%")
                )
            
            if filters.get('date_from'):
                query = query.filter(Case.created_at >= filters['date_from'])
            
            if filters.get('date_to'):
                query = query.filter(Case.created_at <= filters['date_to'])
            
            # Order by creation date descending
            cases = query.order_by(desc(Case.created_at)).limit(100).all()
            
            result = []
            for case in cases:
                # Get assignee username
                assignee_name = None
                if case.assigned_to:
                    assignee = db.query(User).filter(User.id == case.assigned_to).first()
                    assignee_name = assignee.username if assignee else None
                
                result.append({
                    'id': case.id,
                    'title': case.title,
                    'description': case.description,
                    'case_type': case.case_type,
                    'priority': case.priority,
                    'status': case.status,
                    'assigned_to': assignee_name,
                    'created_at': case.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                    'updated_at': case.updated_at.strftime('%Y-%m-%d %H:%M:%S') if case.updated_at else None,
                    'resolved_at': case.resolved_at.strftime('%Y-%m-%d %H:%M:%S') if case.resolved_at else None,
                    'resolution': case.resolution
                })
            
            db.close()
            return result
            
        except Exception as e:
            logger.error(f"Error getting filtered cases: {e}")
            return []
    
    async def get_case_summary(self) -> Dict[str, Any]:
        """Get case summary statistics"""
        cache_key = "case_summary"
        
        if self._is_cache_valid(cache_key):
            return self.cache[cache_key]['data']
        
        try:
            db = SessionLocal()
            
            # Count cases by status
            open_cases = db.query(Case).filter(Case.status == 'open').count()
            in_progress_cases = db.query(Case).filter(Case.status == 'in_progress').count()
            resolved_cases = db.query(Case).filter(Case.status == 'resolved').count()
            
            # High priority cases
            high_priority_cases = db.query(Case).filter(
                and_(Case.priority == 'high', Case.status.in_(['open', 'in_progress']))
            ).count()
            
            summary = {
                'open': open_cases,
                'in_progress': in_progress_cases,
                'resolved': resolved_cases,
                'high_priority': high_priority_cases,
                'total_active': open_cases + in_progress_cases
            }
            
            self._cache_data(cache_key, summary)
            db.close()
            return summary
            
        except Exception as e:
            logger.error(f"Error getting case summary: {e}")
            return {'open': 0, 'in_progress': 0, 'resolved': 0, 'high_priority': 0, 'total_active': 0}
    
    async def create_case(self, case_data: Dict[str, Any]) -> int:
        """Create a new investigation case"""
        try:
            db = SessionLocal()
            
            # Get assignee ID if username provided
            assigned_to_id = None
            if case_data.get('assigned_to'):
                assignee = db.query(User).filter(User.username == case_data['assigned_to']).first()
                if assignee:
                    assigned_to_id = assignee.id
            
            case = Case(
                title=case_data['title'],
                description=case_data.get('description', ''),
                case_type=case_data.get('case_type', 'fraud_investigation'),
                priority=case_data.get('priority', 'medium'),
                status='open',
                assigned_to=assigned_to_id,
                created_by=1  # Default to admin user for demo
            )
            
            db.add(case)
            db.commit()
            case_id = case.id
            db.close()
            
            logger.info(f"📋 Created case {case_id}: {case_data['title']}")
            return case_id
            
        except Exception as e:
            logger.error(f"Error creating case: {e}")
            raise
    
    async def create_case_from_alert(self, alert_id: int) -> int:
        """Create a case from a single alert"""
        try:
            db = SessionLocal()
            
            # Get alert details
            alert = db.query(Alert).filter(Alert.id == alert_id).first()
            
            if not alert:
                raise ValueError(f"Alert {alert_id} not found")
            
            # Create case
            case = Case(
                title=f"Investigation: {alert.title}",
                description=f"Case created from alert {alert_id}: {alert.description}",
                case_type='fraud_investigation',
                priority='high' if alert.severity == 'high' else 'medium',
                status='open',
                assigned_to=alert.assigned_to,
                created_by=1  # Default to admin user for demo
            )
            
            db.add(case)
            db.commit()
            case_id = case.id
            
            # Link alert to case
            case_alert = CaseAlert(
                case_id=case_id,
                alert_id=alert_id
            )
            db.add(case_alert)
            
            # Update alert status
            alert.status = 'in_progress'
            alert.updated_at = datetime.now()
            
            db.commit()
            db.close()
            
            logger.info(f"📋 Created case {case_id} from alert {alert_id}")
            return case_id
            
        except Exception as e:
            logger.error(f"Error creating case from alert {alert_id}: {e}")
            raise
    
    async def create_case_from_alerts(self, alert_ids: List[int]) -> int:
        """Create a case from multiple alerts"""
        try:
            db = SessionLocal()
            
            # Get alert details
            alerts = db.query(Alert).filter(Alert.id.in_(alert_ids)).all()
            
            if not alerts:
                raise ValueError("No valid alerts found")
            
            # Determine case priority based on alert severities
            severities = [alert.severity for alert in alerts]
            if 'high' in severities:
                priority = 'high'
            elif 'medium' in severities:
                priority = 'medium'
            else:
                priority = 'low'
            
            # Create case
            case = Case(
                title=f"Multi-Alert Investigation ({len(alerts)} alerts)",
                description=f"Case created from {len(alerts)} related alerts: {', '.join([str(a.id) for a in alerts])}",
                case_type='fraud_investigation',
                priority=priority,
                status='open',
                created_by=1  # Default to admin user for demo
            )
            
            db.add(case)
            db.commit()
            case_id = case.id
            
            # Link all alerts to case
            for alert in alerts:
                case_alert = CaseAlert(
                    case_id=case_id,
                    alert_id=alert.id
                )
                db.add(case_alert)
                
                # Update alert status
                alert.status = 'in_progress'
                alert.updated_at = datetime.now()
            
            db.commit()
            db.close()
            
            logger.info(f"📋 Created case {case_id} from {len(alerts)} alerts")
            return case_id
            
        except Exception as e:
            logger.error(f"Error creating case from alerts: {e}")
            raise
    
    async def update_case(self, case_id: int, updates: Dict[str, Any]) -> bool:
        """Update an existing case"""
        try:
            db = SessionLocal()
            
            case = db.query(Case).filter(Case.id == case_id).first()
            
            if not case:
                db.close()
                return False
            
            # Update fields
            if 'title' in updates:
                case.title = updates['title']
            
            if 'description' in updates:
                case.description = updates['description']
            
            if 'priority' in updates:
                case.priority = updates['priority']
            
            if 'status' in updates:
                case.status = updates['status']
                if updates['status'] == 'resolved':
                    case.resolved_at = datetime.now()
            
            if 'assigned_to' in updates:
                # Handle username to ID conversion
                if isinstance(updates['assigned_to'], str):
                    assignee = db.query(User).filter(User.username == updates['assigned_to']).first()
                    case.assigned_to = assignee.id if assignee else None
                else:
                    case.assigned_to = updates['assigned_to']
            
            if 'resolution' in updates:
                case.resolution = updates['resolution']
            
            case.updated_at = datetime.now()
            
            db.commit()
            db.close()
            
            logger.info(f"✅ Updated case {case_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error updating case {case_id}: {e}")
            return False
    
    async def get_case_alerts(self, case_id: int) -> List[Dict[str, Any]]:
        """Get alerts associated with a case"""
        try:
            db = SessionLocal()
            
            # Get alerts linked to this case
            case_alerts = db.query(CaseAlert).filter(CaseAlert.case_id == case_id).all()
            alert_ids = [ca.alert_id for ca in case_alerts]
            
            if not alert_ids:
                db.close()
                return []
            
            alerts = db.query(Alert).filter(Alert.id.in_(alert_ids)).all()
            
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
                    'transaction_id': alert.transaction_id
                })
            
            db.close()
            return result
            
        except Exception as e:
            logger.error(f"Error getting case alerts for {case_id}: {e}")
            return []
    
    async def get_case_notes(self, case_id: int) -> List[Dict[str, Any]]:
        """Get investigation notes for a case"""
        try:
            db = SessionLocal()
            
            investigations = db.query(Investigation).filter(
                Investigation.case_id == case_id
            ).order_by(desc(Investigation.created_at)).all()
            
            result = []
            for investigation in investigations:
                # Get investigator username
                investigator = db.query(User).filter(User.id == investigation.investigator_id).first()
                investigator_name = investigator.username if investigator else 'Unknown'
                
                result.append({
                    'id': investigation.id,
                    'notes': investigation.notes,
                    'investigation_type': investigation.investigation_type,
                    'evidence': investigation.evidence,
                    'investigator': investigator_name,
                    'created_at': investigation.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                    'content': investigation.notes  # Alias for compatibility
                })
            
            db.close()
            return result
            
        except Exception as e:
            logger.error(f"Error getting case notes for {case_id}: {e}")
            return []
    
    async def add_case_note(self, case_id: int, notes: str, investigator_username: str, 
                           investigation_type: str = 'general', evidence: Dict[str, Any] = None) -> int:
        """Add investigation note to a case"""
        try:
            db = SessionLocal()
            
            # Get investigator ID
            investigator = db.query(User).filter(User.username == investigator_username).first()
            if not investigator:
                # For demo purposes, create a default investigator entry
                investigator_id = 1  # Default to admin
            else:
                investigator_id = investigator.id
            
            investigation = Investigation(
                case_id=case_id,
                investigator_id=investigator_id,
                notes=notes,
                investigation_type=investigation_type,
                evidence=evidence or {}
            )
            
            db.add(investigation)
            db.commit()
            investigation_id = investigation.id
            
            # Update case timestamp
            case = db.query(Case).filter(Case.id == case_id).first()
            if case:
                case.updated_at = datetime.now()
                db.commit()
            
            db.close()
            
            logger.info(f"📝 Added investigation note {investigation_id} to case {case_id}")
            return investigation_id
            
        except Exception as e:
            logger.error(f"Error adding case note: {e}")
            raise
    
    async def get_case_details(self, case_id: int) -> Optional[Dict[str, Any]]:
        """Get detailed information about a specific case"""
        try:
            db = SessionLocal()
            
            case = db.query(Case).filter(Case.id == case_id).first()
            
            if not case:
                db.close()
                return None
            
            # Get assignee details
            assignee = None
            if case.assigned_to:
                assignee_user = db.query(User).filter(User.id == case.assigned_to).first()
                if assignee_user:
                    assignee = {
                        'id': assignee_user.id,
                        'username': assignee_user.username,
                        'full_name': assignee_user.full_name
                    }
            
            # Get creator details
            creator = None
            if case.created_by:
                creator_user = db.query(User).filter(User.id == case.created_by).first()
                if creator_user:
                    creator = {
                        'id': creator_user.id,
                        'username': creator_user.username,
                        'full_name': creator_user.full_name
                    }
            
            result = {
                'id': case.id,
                'title': case.title,
                'description': case.description,
                'case_type': case.case_type,
                'priority': case.priority,
                'status': case.status,
                'resolution': case.resolution,
                'created_at': case.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                'updated_at': case.updated_at.strftime('%Y-%m-%d %H:%M:%S') if case.updated_at else None,
                'resolved_at': case.resolved_at.strftime('%Y-%m-%d %H:%M:%S') if case.resolved_at else None,
                'assignee': assignee,
                'creator': creator
            }
            
            db.close()
            return result
            
        except Exception as e:
            logger.error(f"Error getting case details for {case_id}: {e}")
            return None
    
    async def get_case_metrics(self) -> Dict[str, Any]:
        """Get case performance metrics"""
        try:
            db = SessionLocal()
            
            # Total cases
            total_cases = db.query(Case).count()
            
            # Cases by status
            open_cases = db.query(Case).filter(Case.status == 'open').count()
            in_progress_cases = db.query(Case).filter(Case.status == 'in_progress').count()
            resolved_cases = db.query(Case).filter(Case.status == 'resolved').count()
            
            # Average resolution time
            resolved_with_times = db.query(Case).filter(
                and_(Case.status == 'resolved', Case.resolved_at.isnot(None))
            ).all()
            
            avg_resolution_days = 0.0
            if resolved_with_times:
                total_days = sum([
                    (case.resolved_at - case.created_at).total_seconds() / (24 * 3600)
                    for case in resolved_with_times
                ])
                avg_resolution_days = total_days / len(resolved_with_times)
            
            # Cases by priority
            high_priority = db.query(Case).filter(Case.priority == 'high').count()
            medium_priority = db.query(Case).filter(Case.priority == 'medium').count()
            low_priority = db.query(Case).filter(Case.priority == 'low').count()
            
            # Recent activity (last 7 days)
            week_ago = datetime.now() - timedelta(days=7)
            recent_cases = db.query(Case).filter(Case.created_at >= week_ago).count()
            recent_resolved = db.query(Case).filter(
                and_(Case.status == 'resolved', Case.resolved_at >= week_ago)
            ).count()
            
            metrics = {
                'total_cases': total_cases,
                'open_cases': open_cases,
                'in_progress_cases': in_progress_cases,
                'resolved_cases': resolved_cases,
                'resolution_rate': (resolved_cases / total_cases * 100) if total_cases > 0 else 0,
                'avg_resolution_days': avg_resolution_days,
                'priority_distribution': {
                    'high': high_priority,
                    'medium': medium_priority,
                    'low': low_priority
                },
                'recent_activity': {
                    'new_cases_week': recent_cases,
                    'resolved_week': recent_resolved
                }
            }
            
            db.close()
            return metrics
            
        except Exception as e:
            logger.error(f"Error getting case metrics: {e}")
            return {}
    
    async def assign_case(self, case_id: int, assignee_username: str) -> bool:
        """Assign a case to a user"""
        try:
            db = SessionLocal()
            
            # Get assignee ID
            assignee = db.query(User).filter(User.username == assignee_username).first()
            if not assignee:
                db.close()
                return False
            
            # Update case
            case = db.query(Case).filter(Case.id == case_id).first()
            if not case:
                db.close()
                return False
            
            case.assigned_to = assignee.id
            case.status = 'in_progress' if case.status == 'open' else case.status
            case.updated_at = datetime.now()
            
            db.commit()
            db.close()
            
            logger.info(f"👤 Assigned case {case_id} to {assignee_username}")
            return True
            
        except Exception as e:
            logger.error(f"Error assigning case {case_id}: {e}")
            return False
    
    async def close_case(self, case_id: int, resolution: str) -> bool:
        """Close a case with resolution notes"""
        try:
            updates = {
                'status': 'resolved',
                'resolution': resolution
            }
            
            success = await self.update_case(case_id, updates)
            
            if success:
                logger.info(f"✅ Closed case {case_id}")
            
            return success
            
        except Exception as e:
            logger.error(f"Error closing case {case_id}: {e}")
            return False
    
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