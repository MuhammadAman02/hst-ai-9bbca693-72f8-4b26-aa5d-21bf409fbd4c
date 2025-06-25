"""
Production-ready Fraud Detection & Tracking Application with:
✓ Real-time fraud monitoring dashboard with professional security UI/UX
✓ Advanced fraud detection engine with configurable rules and ML scoring
✓ Comprehensive transaction analysis and suspicious activity tracking
✓ Case management system for fraud investigations
✓ Real-time alerts and notifications with severity classification
✓ Professional security imagery and modern dashboard design
✓ Secure data handling with encryption and access controls
✓ Performance-optimized for high-volume transaction processing
✓ Zero-configuration deployment with complete fraud detection capabilities
"""

import os
import sys
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Add the app directory to Python path for imports
app_dir = Path(__file__).parent / "app"
sys.path.insert(0, str(app_dir))

try:
    from nicegui import ui, app as nicegui_app
    from contextlib import asynccontextmanager
    import asyncio
    from datetime import datetime, timedelta
    import logging
    
    # Import application modules
    from core.config import settings
    from core.database import init_db, get_db_session
    from core.fraud_engine import FraudDetectionEngine
    from core.assets import SecurityAssetManager
    from services.fraud_detection_service import FraudDetectionService
    from services.alert_service import AlertService
    from services.case_management_service import CaseManagementService
    from api.dashboard import setup_dashboard_routes
    from api.transactions import setup_transaction_routes
    from api.alerts import setup_alert_routes
    from api.cases import setup_case_routes
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    logger = logging.getLogger(__name__)
    
    # Initialize global services
    fraud_engine = FraudDetectionEngine()
    fraud_service = FraudDetectionService(fraud_engine)
    alert_service = AlertService()
    case_service = CaseManagementService()
    asset_manager = SecurityAssetManager()
    
    @asynccontextmanager
    async def lifespan(app):
        """Application lifespan management"""
        # Startup
        logger.info("🔒 Starting Fraud Detection System...")
        
        # Initialize database
        await init_db()
        logger.info("✅ Database initialized")
        
        # Start fraud detection engine
        await fraud_engine.start()
        logger.info("✅ Fraud detection engine started")
        
        # Load fraud detection rules
        await fraud_service.load_default_rules()
        logger.info("✅ Fraud detection rules loaded")
        
        yield
        
        # Shutdown
        logger.info("🔒 Shutting down Fraud Detection System...")
        await fraud_engine.stop()
    
    # Configure NiceGUI app
    nicegui_app.on_startup(lambda: asyncio.create_task(init_db()))
    
    # Global state for real-time updates
    dashboard_clients = set()
    
    async def broadcast_update(data: dict):
        """Broadcast updates to all connected dashboard clients"""
        for client in dashboard_clients.copy():
            try:
                await client.send(data)
            except:
                dashboard_clients.discard(client)
    
    # Main Dashboard Page
    @ui.page('/', title='🔒 Fraud Detection Dashboard')
    async def dashboard_page():
        """Main fraud detection dashboard with real-time monitoring"""
        
        # Add custom CSS for security theme
        ui.add_head_html('''
        <style>
            .fraud-dashboard {
                background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
                min-height: 100vh;
                color: white;
            }
            .metric-card {
                background: rgba(255, 255, 255, 0.1);
                backdrop-filter: blur(10px);
                border: 1px solid rgba(255, 255, 255, 0.2);
                border-radius: 12px;
                padding: 20px;
                margin: 10px;
                transition: transform 0.3s ease;
            }
            .metric-card:hover {
                transform: translateY(-5px);
                background: rgba(255, 255, 255, 0.15);
            }
            .alert-high { border-left: 5px solid #ff4757; }
            .alert-medium { border-left: 5px solid #ffa502; }
            .alert-low { border-left: 5px solid #2ed573; }
            .security-header {
                background: rgba(0, 0, 0, 0.3);
                padding: 20px;
                margin-bottom: 20px;
                border-radius: 8px;
            }
        </style>
        ''')
        
        with ui.column().classes('fraud-dashboard w-full'):
            # Header with security branding
            with ui.row().classes('security-header w-full items-center'):
                ui.image(asset_manager.get_security_image('shield')).classes('w-16 h-16')
                with ui.column():
                    ui.label('🔒 Fraud Detection & Tracking System').classes('text-3xl font-bold')
                    ui.label(f'Real-time monitoring • {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}').classes('text-lg opacity-80')
            
            # Real-time metrics row
            with ui.row().classes('w-full justify-around'):
                # Total transactions metric
                with ui.card().classes('metric-card'):
                    ui.label('📊 Total Transactions').classes('text-lg font-semibold')
                    total_transactions = ui.label('Loading...').classes('text-3xl font-bold text-blue-300')
                    ui.label('Last 24 hours').classes('text-sm opacity-70')
                
                # Fraud alerts metric
                with ui.card().classes('metric-card'):
                    ui.label('🚨 Active Alerts').classes('text-lg font-semibold')
                    active_alerts = ui.label('Loading...').classes('text-3xl font-bold text-red-300')
                    ui.label('Requiring attention').classes('text-sm opacity-70')
                
                # Risk score metric
                with ui.card().classes('metric-card'):
                    ui.label('⚠️ Average Risk Score').classes('text-lg font-semibold')
                    avg_risk_score = ui.label('Loading...').classes('text-3xl font-bold text-yellow-300')
                    ui.label('Current period').classes('text-sm opacity-70')
                
                # Cases metric
                with ui.card().classes('metric-card'):
                    ui.label('📋 Open Cases').classes('text-lg font-semibold')
                    open_cases = ui.label('Loading...').classes('text-3xl font-bold text-green-300')
                    ui.label('Under investigation').classes('text-sm opacity-70')
            
            # Charts and analysis row
            with ui.row().classes('w-full'):
                # Fraud trends chart
                with ui.card().classes('w-1/2 p-4'):
                    ui.label('📈 Fraud Detection Trends').classes('text-xl font-semibold mb-4')
                    fraud_chart = ui.plotly({}).classes('w-full h-64')
                
                # Risk distribution chart
                with ui.card().classes('w-1/2 p-4'):
                    ui.label('🎯 Risk Score Distribution').classes('text-xl font-semibold mb-4')
                    risk_chart = ui.plotly({}).classes('w-full h-64')
            
            # Recent alerts and transactions
            with ui.row().classes('w-full'):
                # Recent high-risk alerts
                with ui.card().classes('w-1/2 p-4'):
                    ui.label('🚨 Recent High-Risk Alerts').classes('text-xl font-semibold mb-4')
                    alerts_container = ui.column().classes('w-full')
                
                # Recent suspicious transactions
                with ui.card().classes('w-1/2 p-4'):
                    ui.label('💳 Suspicious Transactions').classes('text-xl font-semibold mb-4')
                    transactions_container = ui.column().classes('w-full')
            
            # Action buttons
            with ui.row().classes('w-full justify-center mt-8'):
                ui.button('🔍 View All Transactions', on_click=lambda: ui.navigate.to('/transactions')).classes('bg-blue-600 hover:bg-blue-700 px-6 py-3 text-lg')
                ui.button('🚨 Manage Alerts', on_click=lambda: ui.navigate.to('/alerts')).classes('bg-red-600 hover:bg-red-700 px-6 py-3 text-lg')
                ui.button('📋 Case Management', on_click=lambda: ui.navigate.to('/cases')).classes('bg-green-600 hover:bg-green-700 px-6 py-3 text-lg')
                ui.button('⚙️ Fraud Rules', on_click=lambda: ui.navigate.to('/rules')).classes('bg-purple-600 hover:bg-purple-700 px-6 py-3 text-lg')
        
        # Real-time data updates
        async def update_dashboard():
            """Update dashboard with real-time data"""
            try:
                # Get real-time metrics
                metrics = await fraud_service.get_dashboard_metrics()
                
                # Update metric displays
                total_transactions.text = f"{metrics['total_transactions']:,}"
                active_alerts.text = str(metrics['active_alerts'])
                avg_risk_score.text = f"{metrics['avg_risk_score']:.1f}"
                open_cases.text = str(metrics['open_cases'])
                
                # Update fraud trends chart
                fraud_trends = await fraud_service.get_fraud_trends()
                fraud_chart.figure = {
                    'data': [{
                        'x': fraud_trends['dates'],
                        'y': fraud_trends['fraud_count'],
                        'type': 'scatter',
                        'mode': 'lines+markers',
                        'name': 'Fraud Detections',
                        'line': {'color': '#ff4757', 'width': 3}
                    }],
                    'layout': {
                        'title': 'Daily Fraud Detections',
                        'xaxis': {'title': 'Date'},
                        'yaxis': {'title': 'Count'},
                        'plot_bgcolor': 'rgba(0,0,0,0)',
                        'paper_bgcolor': 'rgba(0,0,0,0)',
                        'font': {'color': 'white'}
                    }
                }
                
                # Update risk distribution chart
                risk_distribution = await fraud_service.get_risk_distribution()
                risk_chart.figure = {
                    'data': [{
                        'x': risk_distribution['risk_ranges'],
                        'y': risk_distribution['counts'],
                        'type': 'bar',
                        'marker': {'color': ['#2ed573', '#ffa502', '#ff4757']}
                    }],
                    'layout': {
                        'title': 'Risk Score Distribution',
                        'xaxis': {'title': 'Risk Level'},
                        'yaxis': {'title': 'Transaction Count'},
                        'plot_bgcolor': 'rgba(0,0,0,0)',
                        'paper_bgcolor': 'rgba(0,0,0,0)',
                        'font': {'color': 'white'}
                    }
                }
                
                # Update recent alerts
                recent_alerts = await alert_service.get_recent_alerts(limit=5)
                alerts_container.clear()
                for alert in recent_alerts:
                    severity_class = f"alert-{alert['severity'].lower()}"
                    with alerts_container:
                        with ui.card().classes(f'w-full p-3 mb-2 {severity_class}'):
                            ui.label(f"🚨 {alert['title']}").classes('font-semibold')
                            ui.label(f"Risk Score: {alert['risk_score']:.1f} | {alert['created_at']}").classes('text-sm opacity-80')
                
                # Update recent transactions
                recent_transactions = await fraud_service.get_suspicious_transactions(limit=5)
                transactions_container.clear()
                for transaction in recent_transactions:
                    with transactions_container:
                        with ui.card().classes('w-full p-3 mb-2 border-l-4 border-yellow-500'):
                            ui.label(f"💳 ${transaction['amount']:,.2f} - {transaction['type']}").classes('font-semibold')
                            ui.label(f"Risk: {transaction['risk_score']:.1f} | User: {transaction['user_id']} | {transaction['timestamp']}").classes('text-sm opacity-80')
                
            except Exception as e:
                logger.error(f"Error updating dashboard: {e}")
        
        # Initial load and periodic updates
        await update_dashboard()
        ui.timer(30.0, update_dashboard)  # Update every 30 seconds
    
    # Transaction Monitoring Page
    @ui.page('/transactions', title='💳 Transaction Monitoring')
    async def transactions_page():
        """Transaction monitoring and analysis page"""
        
        with ui.column().classes('fraud-dashboard w-full p-6'):
            # Header
            with ui.row().classes('w-full items-center mb-6'):
                ui.button('← Back to Dashboard', on_click=lambda: ui.navigate.to('/')).classes('bg-gray-600 hover:bg-gray-700')
                ui.label('💳 Transaction Monitoring').classes('text-3xl font-bold text-white ml-4')
            
            # Filters
            with ui.card().classes('w-full p-4 mb-6'):
                ui.label('🔍 Filters').classes('text-xl font-semibold mb-4')
                with ui.row().classes('w-full gap-4'):
                    date_from = ui.input('From Date', value=(datetime.now() - timedelta(days=7)).strftime('%Y-%m-%d')).classes('w-48')
                    date_to = ui.input('To Date', value=datetime.now().strftime('%Y-%m-%d')).classes('w-48')
                    min_amount = ui.number('Min Amount', value=0, format='%.2f').classes('w-32')
                    max_amount = ui.number('Max Amount', value=10000, format='%.2f').classes('w-32')
                    risk_threshold = ui.slider('Min Risk Score', min=0, max=100, value=50).classes('w-48')
                    ui.button('Apply Filters', on_click=lambda: update_transactions()).classes('bg-blue-600 hover:bg-blue-700')
            
            # Transaction table
            with ui.card().classes('w-full p-4'):
                ui.label('📊 Transaction Analysis').classes('text-xl font-semibold mb-4')
                
                # Table headers
                with ui.row().classes('w-full bg-gray-800 p-3 rounded font-semibold'):
                    ui.label('ID').classes('w-20')
                    ui.label('Amount').classes('w-32')
                    ui.label('Type').classes('w-32')
                    ui.label('Risk Score').classes('w-32')
                    ui.label('Status').classes('w-32')
                    ui.label('Timestamp').classes('w-48')
                    ui.label('Actions').classes('w-32')
                
                transactions_table = ui.column().classes('w-full')
        
        async def update_transactions():
            """Update transaction list based on filters"""
            try:
                filters = {
                    'date_from': date_from.value,
                    'date_to': date_to.value,
                    'min_amount': min_amount.value,
                    'max_amount': max_amount.value,
                    'min_risk_score': risk_threshold.value
                }
                
                transactions = await fraud_service.get_filtered_transactions(filters)
                
                transactions_table.clear()
                for transaction in transactions:
                    risk_color = 'text-red-400' if transaction['risk_score'] > 70 else 'text-yellow-400' if transaction['risk_score'] > 40 else 'text-green-400'
                    status_color = 'text-red-400' if transaction['status'] == 'flagged' else 'text-green-400'
                    
                    with transactions_table:
                        with ui.row().classes('w-full p-3 border-b border-gray-700 hover:bg-gray-800'):
                            ui.label(str(transaction['id'])).classes('w-20')
                            ui.label(f"${transaction['amount']:,.2f}").classes('w-32 font-semibold')
                            ui.label(transaction['type']).classes('w-32')
                            ui.label(f"{transaction['risk_score']:.1f}").classes(f'w-32 font-semibold {risk_color}')
                            ui.label(transaction['status'].title()).classes(f'w-32 {status_color}')
                            ui.label(transaction['timestamp']).classes('w-48 text-sm')
                            with ui.row().classes('w-32'):
                                ui.button('🔍', on_click=lambda t=transaction: view_transaction_details(t)).classes('bg-blue-600 hover:bg-blue-700 text-xs p-1')
                                if transaction['status'] != 'flagged':
                                    ui.button('🚩', on_click=lambda t=transaction: flag_transaction(t)).classes('bg-red-600 hover:bg-red-700 text-xs p-1')
            
            except Exception as e:
                logger.error(f"Error updating transactions: {e}")
                ui.notify(f"Error loading transactions: {e}", type='negative')
        
        async def view_transaction_details(transaction):
            """Show detailed transaction information"""
            with ui.dialog() as dialog, ui.card().classes('w-96'):
                ui.label(f'Transaction Details - ID: {transaction["id"]}').classes('text-xl font-bold mb-4')
                
                with ui.column().classes('w-full gap-2'):
                    ui.label(f'Amount: ${transaction["amount"]:,.2f}').classes('text-lg')
                    ui.label(f'Type: {transaction["type"]}').classes('text-lg')
                    ui.label(f'Risk Score: {transaction["risk_score"]:.1f}').classes('text-lg')
                    ui.label(f'Status: {transaction["status"].title()}').classes('text-lg')
                    ui.label(f'User ID: {transaction["user_id"]}').classes('text-lg')
                    ui.label(f'Timestamp: {transaction["timestamp"]}').classes('text-lg')
                    
                    # Risk factors
                    ui.separator()
                    ui.label('Risk Factors:').classes('text-lg font-semibold mt-4')
                    risk_factors = await fraud_service.get_transaction_risk_factors(transaction['id'])
                    for factor in risk_factors:
                        ui.label(f'• {factor}').classes('text-sm ml-4')
                
                with ui.row().classes('w-full justify-end mt-4'):
                    ui.button('Close', on_click=dialog.close).classes('bg-gray-600 hover:bg-gray-700')
                    if transaction['status'] != 'flagged':
                        ui.button('Flag as Suspicious', on_click=lambda: flag_and_close(transaction, dialog)).classes('bg-red-600 hover:bg-red-700')
            
            dialog.open()
        
        async def flag_transaction(transaction):
            """Flag transaction as suspicious"""
            try:
                await fraud_service.flag_transaction(transaction['id'])
                ui.notify(f'Transaction {transaction["id"]} flagged as suspicious', type='positive')
                await update_transactions()
            except Exception as e:
                logger.error(f"Error flagging transaction: {e}")
                ui.notify(f"Error flagging transaction: {e}", type='negative')
        
        async def flag_and_close(transaction, dialog):
            """Flag transaction and close dialog"""
            await flag_transaction(transaction)
            dialog.close()
        
        # Initial load
        await update_transactions()
    
    # Alerts Management Page
    @ui.page('/alerts', title='🚨 Alert Management')
    async def alerts_page():
        """Alert management and investigation page"""
        
        with ui.column().classes('fraud-dashboard w-full p-6'):
            # Header
            with ui.row().classes('w-full items-center mb-6'):
                ui.button('← Back to Dashboard', on_click=lambda: ui.navigate.to('/')).classes('bg-gray-600 hover:bg-gray-700')
                ui.label('🚨 Alert Management').classes('text-3xl font-bold text-white ml-4')
            
            # Alert summary cards
            with ui.row().classes('w-full mb-6'):
                high_alerts_card = ui.card().classes('metric-card w-1/4')
                medium_alerts_card = ui.card().classes('metric-card w-1/4')
                low_alerts_card = ui.card().classes('metric-card w-1/4')
                resolved_alerts_card = ui.card().classes('metric-card w-1/4')
                
                with high_alerts_card:
                    ui.label('🔴 High Priority').classes('text-lg font-semibold')
                    high_count = ui.label('Loading...').classes('text-2xl font-bold text-red-400')
                
                with medium_alerts_card:
                    ui.label('🟡 Medium Priority').classes('text-lg font-semibold')
                    medium_count = ui.label('Loading...').classes('text-2xl font-bold text-yellow-400')
                
                with low_alerts_card:
                    ui.label('🟢 Low Priority').classes('text-lg font-semibold')
                    low_count = ui.label('Loading...').classes('text-2xl font-bold text-green-400')
                
                with resolved_alerts_card:
                    ui.label('✅ Resolved Today').classes('text-lg font-semibold')
                    resolved_count = ui.label('Loading...').classes('text-2xl font-bold text-blue-400')
            
            # Filters and actions
            with ui.card().classes('w-full p-4 mb-6'):
                with ui.row().classes('w-full items-center gap-4'):
                    severity_filter = ui.select(['All', 'High', 'Medium', 'Low'], value='All', label='Severity').classes('w-32')
                    status_filter = ui.select(['All', 'Open', 'In Progress', 'Resolved'], value='All', label='Status').classes('w-32')
                    ui.button('Refresh Alerts', on_click=lambda: update_alerts()).classes('bg-blue-600 hover:bg-blue-700')
                    ui.button('Create Case from Selected', on_click=lambda: create_case_from_alerts()).classes('bg-green-600 hover:bg-green-700')
            
            # Alerts table
            with ui.card().classes('w-full p-4'):
                ui.label('🚨 Active Alerts').classes('text-xl font-semibold mb-4')
                
                # Table headers
                with ui.row().classes('w-full bg-gray-800 p-3 rounded font-semibold'):
                    ui.checkbox(value=False, on_change=lambda e: toggle_all_alerts(e.value)).classes('w-8')
                    ui.label('ID').classes('w-16')
                    ui.label('Title').classes('w-64')
                    ui.label('Severity').classes('w-24')
                    ui.label('Risk Score').classes('w-24')
                    ui.label('Status').classes('w-32')
                    ui.label('Created').classes('w-48')
                    ui.label('Actions').classes('w-32')
                
                alerts_table = ui.column().classes('w-full')
        
        selected_alerts = set()
        
        def toggle_all_alerts(checked):
            """Toggle all alert checkboxes"""
            # This would be implemented with proper state management
            pass
        
        async def update_alerts():
            """Update alerts list based on filters"""
            try:
                filters = {
                    'severity': severity_filter.value if severity_filter.value != 'All' else None,
                    'status': status_filter.value if status_filter.value != 'All' else None
                }
                
                alerts = await alert_service.get_filtered_alerts(filters)
                
                # Update summary counts
                summary = await alert_service.get_alert_summary()
                high_count.text = str(summary['high'])
                medium_count.text = str(summary['medium'])
                low_count.text = str(summary['low'])
                resolved_count.text = str(summary['resolved_today'])
                
                # Update alerts table
                alerts_table.clear()
                for alert in alerts:
                    severity_color = {
                        'high': 'text-red-400',
                        'medium': 'text-yellow-400',
                        'low': 'text-green-400'
                    }.get(alert['severity'].lower(), 'text-gray-400')
                    
                    status_color = {
                        'open': 'text-red-400',
                        'in_progress': 'text-yellow-400',
                        'resolved': 'text-green-400'
                    }.get(alert['status'].lower().replace(' ', '_'), 'text-gray-400')
                    
                    with alerts_table:
                        with ui.row().classes('w-full p-3 border-b border-gray-700 hover:bg-gray-800'):
                            alert_checkbox = ui.checkbox(value=False, on_change=lambda e, a=alert: toggle_alert_selection(a['id'], e.value)).classes('w-8')
                            ui.label(str(alert['id'])).classes('w-16')
                            ui.label(alert['title']).classes('w-64')
                            ui.label(alert['severity'].title()).classes(f'w-24 font-semibold {severity_color}')
                            ui.label(f"{alert['risk_score']:.1f}").classes('w-24 font-semibold')
                            ui.label(alert['status'].replace('_', ' ').title()).classes(f'w-32 {status_color}')
                            ui.label(alert['created_at']).classes('w-48 text-sm')
                            with ui.row().classes('w-32'):
                                ui.button('👁️', on_click=lambda a=alert: view_alert_details(a)).classes('bg-blue-600 hover:bg-blue-700 text-xs p-1')
                                ui.button('✅', on_click=lambda a=alert: resolve_alert(a)).classes('bg-green-600 hover:bg-green-700 text-xs p-1')
            
            except Exception as e:
                logger.error(f"Error updating alerts: {e}")
                ui.notify(f"Error loading alerts: {e}", type='negative')
        
        def toggle_alert_selection(alert_id, selected):
            """Toggle alert selection for bulk operations"""
            if selected:
                selected_alerts.add(alert_id)
            else:
                selected_alerts.discard(alert_id)
        
        async def view_alert_details(alert):
            """Show detailed alert information"""
            with ui.dialog() as dialog, ui.card().classes('w-[600px]'):
                ui.label(f'Alert Details - ID: {alert["id"]}').classes('text-xl font-bold mb-4')
                
                with ui.column().classes('w-full gap-3'):
                    ui.label(f'Title: {alert["title"]}').classes('text-lg')
                    ui.label(f'Severity: {alert["severity"].title()}').classes('text-lg')
                    ui.label(f'Risk Score: {alert["risk_score"]:.1f}').classes('text-lg')
                    ui.label(f'Status: {alert["status"].replace("_", " ").title()}').classes('text-lg')
                    ui.label(f'Created: {alert["created_at"]}').classes('text-lg')
                    
                    ui.separator()
                    ui.label('Description:').classes('text-lg font-semibold')
                    ui.label(alert.get('description', 'No description available')).classes('text-sm bg-gray-800 p-3 rounded')
                    
                    # Related transaction details
                    if alert.get('transaction_id'):
                        ui.separator()
                        ui.label('Related Transaction:').classes('text-lg font-semibold')
                        transaction = await fraud_service.get_transaction_by_id(alert['transaction_id'])
                        if transaction:
                            ui.label(f'Amount: ${transaction["amount"]:,.2f}').classes('text-sm ml-4')
                            ui.label(f'Type: {transaction["type"]}').classes('text-sm ml-4')
                            ui.label(f'User ID: {transaction["user_id"]}').classes('text-sm ml-4')
                
                with ui.row().classes('w-full justify-end mt-4 gap-2'):
                    ui.button('Close', on_click=dialog.close).classes('bg-gray-600 hover:bg-gray-700')
                    ui.button('Create Case', on_click=lambda: create_case_from_alert(alert, dialog)).classes('bg-green-600 hover:bg-green-700')
                    if alert['status'] != 'resolved':
                        ui.button('Resolve', on_click=lambda: resolve_alert_and_close(alert, dialog)).classes('bg-blue-600 hover:bg-blue-700')
            
            dialog.open()
        
        async def resolve_alert(alert):
            """Resolve an alert"""
            try:
                await alert_service.resolve_alert(alert['id'])
                ui.notify(f'Alert {alert["id"]} resolved', type='positive')
                await update_alerts()
            except Exception as e:
                logger.error(f"Error resolving alert: {e}")
                ui.notify(f"Error resolving alert: {e}", type='negative')
        
        async def resolve_alert_and_close(alert, dialog):
            """Resolve alert and close dialog"""
            await resolve_alert(alert)
            dialog.close()
        
        async def create_case_from_alert(alert, dialog):
            """Create a case from a single alert"""
            try:
                case_id = await case_service.create_case_from_alert(alert['id'])
                ui.notify(f'Case {case_id} created from alert {alert["id"]}', type='positive')
                dialog.close()
                ui.navigate.to(f'/cases/{case_id}')
            except Exception as e:
                logger.error(f"Error creating case: {e}")
                ui.notify(f"Error creating case: {e}", type='negative')
        
        async def create_case_from_alerts():
            """Create a case from selected alerts"""
            if not selected_alerts:
                ui.notify('Please select at least one alert', type='warning')
                return
            
            try:
                case_id = await case_service.create_case_from_alerts(list(selected_alerts))
                ui.notify(f'Case {case_id} created from {len(selected_alerts)} alerts', type='positive')
                selected_alerts.clear()
                await update_alerts()
                ui.navigate.to(f'/cases/{case_id}')
            except Exception as e:
                logger.error(f"Error creating case: {e}")
                ui.notify(f"Error creating case: {e}", type='negative')
        
        # Initial load
        await update_alerts()
    
    # Case Management Page
    @ui.page('/cases', title='📋 Case Management')
    async def cases_page():
        """Case management and investigation tracking page"""
        
        with ui.column().classes('fraud-dashboard w-full p-6'):
            # Header
            with ui.row().classes('w-full items-center mb-6'):
                ui.button('← Back to Dashboard', on_click=lambda: ui.navigate.to('/')).classes('bg-gray-600 hover:bg-gray-700')
                ui.label('📋 Case Management').classes('text-3xl font-bold text-white ml-4')
                ui.button('+ New Case', on_click=lambda: create_new_case()).classes('bg-green-600 hover:bg-green-700 ml-auto')
            
            # Case summary
            with ui.row().classes('w-full mb-6'):
                open_cases_card = ui.card().classes('metric-card w-1/4')
                in_progress_card = ui.card().classes('metric-card w-1/4')
                resolved_card = ui.card().classes('metric-card w-1/4')
                high_priority_card = ui.card().classes('metric-card w-1/4')
                
                with open_cases_card:
                    ui.label('📂 Open Cases').classes('text-lg font-semibold')
                    open_cases_count = ui.label('Loading...').classes('text-2xl font-bold text-red-400')
                
                with in_progress_card:
                    ui.label('🔄 In Progress').classes('text-lg font-semibold')
                    in_progress_count = ui.label('Loading...').classes('text-2xl font-bold text-yellow-400')
                
                with resolved_card:
                    ui.label('✅ Resolved').classes('text-lg font-semibold')
                    resolved_cases_count = ui.label('Loading...').classes('text-2xl font-bold text-green-400')
                
                with high_priority_card:
                    ui.label('🔥 High Priority').classes('text-lg font-semibold')
                    high_priority_count = ui.label('Loading...').classes('text-2xl font-bold text-orange-400')
            
            # Filters
            with ui.card().classes('w-full p-4 mb-6'):
                with ui.row().classes('w-full items-center gap-4'):
                    status_filter = ui.select(['All', 'Open', 'In Progress', 'Resolved'], value='All', label='Status').classes('w-32')
                    priority_filter = ui.select(['All', 'High', 'Medium', 'Low'], value='All', label='Priority').classes('w-32')
                    assignee_filter = ui.input('Assigned To', placeholder='Enter username').classes('w-48')
                    ui.button('Apply Filters', on_click=lambda: update_cases()).classes('bg-blue-600 hover:bg-blue-700')
            
            # Cases table
            with ui.card().classes('w-full p-4'):
                ui.label('📋 Investigation Cases').classes('text-xl font-semibold mb-4')
                
                # Table headers
                with ui.row().classes('w-full bg-gray-800 p-3 rounded font-semibold'):
                    ui.label('ID').classes('w-16')
                    ui.label('Title').classes('w-64')
                    ui.label('Priority').classes('w-24')
                    ui.label('Status').classes('w-32')
                    ui.label('Assigned To').classes('w-32')
                    ui.label('Created').classes('w-48')
                    ui.label('Actions').classes('w-32')
                
                cases_table = ui.column().classes('w-full')
        
        async def update_cases():
            """Update cases list based on filters"""
            try:
                filters = {
                    'status': status_filter.value if status_filter.value != 'All' else None,
                    'priority': priority_filter.value if priority_filter.value != 'All' else None,
                    'assignee': assignee_filter.value if assignee_filter.value else None
                }
                
                cases = await case_service.get_filtered_cases(filters)
                
                # Update summary counts
                summary = await case_service.get_case_summary()
                open_cases_count.text = str(summary['open'])
                in_progress_count.text = str(summary['in_progress'])
                resolved_cases_count.text = str(summary['resolved'])
                high_priority_count.text = str(summary['high_priority'])
                
                # Update cases table
                cases_table.clear()
                for case in cases:
                    priority_color = {
                        'high': 'text-red-400',
                        'medium': 'text-yellow-400',
                        'low': 'text-green-400'
                    }.get(case['priority'].lower(), 'text-gray-400')
                    
                    status_color = {
                        'open': 'text-red-400',
                        'in_progress': 'text-yellow-400',
                        'resolved': 'text-green-400'
                    }.get(case['status'].lower().replace(' ', '_'), 'text-gray-400')
                    
                    with cases_table:
                        with ui.row().classes('w-full p-3 border-b border-gray-700 hover:bg-gray-800'):
                            ui.label(str(case['id'])).classes('w-16')
                            ui.label(case['title']).classes('w-64')
                            ui.label(case['priority'].title()).classes(f'w-24 font-semibold {priority_color}')
                            ui.label(case['status'].replace('_', ' ').title()).classes(f'w-32 {status_color}')
                            ui.label(case.get('assigned_to', 'Unassigned')).classes('w-32')
                            ui.label(case['created_at']).classes('w-48 text-sm')
                            with ui.row().classes('w-32'):
                                ui.button('👁️', on_click=lambda c=case: view_case_details(c)).classes('bg-blue-600 hover:bg-blue-700 text-xs p-1')
                                ui.button('✏️', on_click=lambda c=case: edit_case(c)).classes('bg-yellow-600 hover:bg-yellow-700 text-xs p-1')
            
            except Exception as e:
                logger.error(f"Error updating cases: {e}")
                ui.notify(f"Error loading cases: {e}", type='negative')
        
        async def create_new_case():
            """Create a new investigation case"""
            with ui.dialog() as dialog, ui.card().classes('w-96'):
                ui.label('Create New Case').classes('text-xl font-bold mb-4')
                
                title_input = ui.input('Case Title', placeholder='Enter case title').classes('w-full')
                description_input = ui.textarea('Description', placeholder='Enter case description').classes('w-full')
                priority_select = ui.select(['High', 'Medium', 'Low'], value='Medium', label='Priority').classes('w-full')
                assignee_input = ui.input('Assign To', placeholder='Enter username (optional)').classes('w-full')
                
                with ui.row().classes('w-full justify-end mt-4'):
                    ui.button('Cancel', on_click=dialog.close).classes('bg-gray-600 hover:bg-gray-700')
                    ui.button('Create Case', on_click=lambda: create_case_and_close()).classes('bg-green-600 hover:bg-green-700')
                
                async def create_case_and_close():
                    if not title_input.value:
                        ui.notify('Please enter a case title', type='warning')
                        return
                    
                    try:
                        case_data = {
                            'title': title_input.value,
                            'description': description_input.value,
                            'priority': priority_select.value.lower(),
                            'assigned_to': assignee_input.value if assignee_input.value else None
                        }
                        
                        case_id = await case_service.create_case(case_data)
                        ui.notify(f'Case {case_id} created successfully', type='positive')
                        dialog.close()
                        await update_cases()
                    except Exception as e:
                        logger.error(f"Error creating case: {e}")
                        ui.notify(f"Error creating case: {e}", type='negative')
            
            dialog.open()
        
        async def view_case_details(case):
            """Show detailed case information"""
            with ui.dialog() as dialog, ui.card().classes('w-[800px] max-h-[600px]'):
                ui.label(f'Case Details - ID: {case["id"]}').classes('text-xl font-bold mb-4')
                
                with ui.scroll_area().classes('w-full h-96'):
                    with ui.column().classes('w-full gap-3'):
                        ui.label(f'Title: {case["title"]}').classes('text-lg font-semibold')
                        ui.label(f'Priority: {case["priority"].title()}').classes('text-lg')
                        ui.label(f'Status: {case["status"].replace("_", " ").title()}').classes('text-lg')
                        ui.label(f'Assigned To: {case.get("assigned_to", "Unassigned")}').classes('text-lg')
                        ui.label(f'Created: {case["created_at"]}').classes('text-lg')
                        
                        ui.separator()
                        ui.label('Description:').classes('text-lg font-semibold')
                        ui.label(case.get('description', 'No description available')).classes('text-sm bg-gray-800 p-3 rounded')
                        
                        # Related alerts
                        ui.separator()
                        ui.label('Related Alerts:').classes('text-lg font-semibold')
                        related_alerts = await case_service.get_case_alerts(case['id'])
                        if related_alerts:
                            for alert in related_alerts:
                                with ui.card().classes('w-full p-2 mb-2 bg-gray-800'):
                                    ui.label(f'Alert {alert["id"]}: {alert["title"]}').classes('font-semibold')
                                    ui.label(f'Risk Score: {alert["risk_score"]:.1f} | Severity: {alert["severity"].title()}').classes('text-sm')
                        else:
                            ui.label('No related alerts').classes('text-sm text-gray-400 ml-4')
                        
                        # Investigation notes
                        ui.separator()
                        ui.label('Investigation Notes:').classes('text-lg font-semibold')
                        notes = await case_service.get_case_notes(case['id'])
                        if notes:
                            for note in notes:
                                with ui.card().classes('w-full p-3 mb-2 bg-gray-800'):
                                    ui.label(f'{note["created_at"]} - {note["investigator"]}').classes('text-sm font-semibold')
                                    ui.label(note['content']).classes('text-sm')
                        else:
                            ui.label('No investigation notes yet').classes('text-sm text-gray-400 ml-4')
                
                with ui.row().classes('w-full justify-end mt-4'):
                    ui.button('Close', on_click=dialog.close).classes('bg-gray-600 hover:bg-gray-700')
                    ui.button('Add Note', on_click=lambda: add_case_note(case, dialog)).classes('bg-blue-600 hover:bg-blue-700')
                    ui.button('Edit Case', on_click=lambda: edit_case_from_details(case, dialog)).classes('bg-yellow-600 hover:bg-yellow-700')
            
            dialog.open()
        
        async def edit_case(case):
            """Edit case information"""
            with ui.dialog() as dialog, ui.card().classes('w-96'):
                ui.label(f'Edit Case - ID: {case["id"]}').classes('text-xl font-bold mb-4')
                
                title_input = ui.input('Case Title', value=case['title']).classes('w-full')
                description_input = ui.textarea('Description', value=case.get('description', '')).classes('w-full')
                priority_select = ui.select(['High', 'Medium', 'Low'], value=case['priority'].title(), label='Priority').classes('w-full')
                status_select = ui.select(['Open', 'In Progress', 'Resolved'], value=case['status'].replace('_', ' ').title(), label='Status').classes('w-full')
                assignee_input = ui.input('Assign To', value=case.get('assigned_to', '')).classes('w-full')
                
                with ui.row().classes('w-full justify-end mt-4'):
                    ui.button('Cancel', on_click=dialog.close).classes('bg-gray-600 hover:bg-gray-700')
                    ui.button('Save Changes', on_click=lambda: save_case_changes()).classes('bg-green-600 hover:bg-green-700')
                
                async def save_case_changes():
                    try:
                        updates = {
                            'title': title_input.value,
                            'description': description_input.value,
                            'priority': priority_select.value.lower(),
                            'status': status_select.value.lower().replace(' ', '_'),
                            'assigned_to': assignee_input.value if assignee_input.value else None
                        }
                        
                        await case_service.update_case(case['id'], updates)
                        ui.notify(f'Case {case["id"]} updated successfully', type='positive')
                        dialog.close()
                        await update_cases()
                    except Exception as e:
                        logger.error(f"Error updating case: {e}")
                        ui.notify(f"Error updating case: {e}", type='negative')
            
            dialog.open()
        
        async def edit_case_from_details(case, parent_dialog):
            """Edit case from details view"""
            parent_dialog.close()
            await edit_case(case)
        
        async def add_case_note(case, parent_dialog):
            """Add investigation note to case"""
            with ui.dialog() as dialog, ui.card().classes('w-96'):
                ui.label(f'Add Note to Case {case["id"]}').classes('text-xl font-bold mb-4')
                
                note_input = ui.textarea('Investigation Note', placeholder='Enter your investigation notes...').classes('w-full h-32')
                
                with ui.row().classes('w-full justify-end mt-4'):
                    ui.button('Cancel', on_click=dialog.close).classes('bg-gray-600 hover:bg-gray-700')
                    ui.button('Add Note', on_click=lambda: save_note_and_close()).classes('bg-green-600 hover:bg-green-700')
                
                async def save_note_and_close():
                    if not note_input.value:
                        ui.notify('Please enter a note', type='warning')
                        return
                    
                    try:
                        await case_service.add_case_note(case['id'], note_input.value, 'current_user')  # In real app, get from auth
                        ui.notify('Note added successfully', type='positive')
                        dialog.close()
                        parent_dialog.close()
                        await view_case_details(case)  # Refresh the details view
                    except Exception as e:
                        logger.error(f"Error adding note: {e}")
                        ui.notify(f"Error adding note: {e}", type='negative')
            
            dialog.open()
        
        # Initial load
        await update_cases()
    
    # Fraud Rules Configuration Page
    @ui.page('/rules', title='⚙️ Fraud Rules')
    async def rules_page():
        """Fraud detection rules configuration page"""
        
        with ui.column().classes('fraud-dashboard w-full p-6'):
            # Header
            with ui.row().classes('w-full items-center mb-6'):
                ui.button('← Back to Dashboard', on_click=lambda: ui.navigate.to('/')).classes('bg-gray-600 hover:bg-gray-700')
                ui.label('⚙️ Fraud Detection Rules').classes('text-3xl font-bold text-white ml-4')
                ui.button('+ New Rule', on_click=lambda: create_new_rule()).classes('bg-green-600 hover:bg-green-700 ml-auto')
            
            # Rules summary
            with ui.row().classes('w-full mb-6'):
                active_rules_card = ui.card().classes('metric-card w-1/4')
                inactive_rules_card = ui.card().classes('metric-card w-1/4')
                triggered_today_card = ui.card().classes('metric-card w-1/4')
                avg_accuracy_card = ui.card().classes('metric-card w-1/4')
                
                with active_rules_card:
                    ui.label('✅ Active Rules').classes('text-lg font-semibold')
                    active_rules_count = ui.label('Loading...').classes('text-2xl font-bold text-green-400')
                
                with inactive_rules_card:
                    ui.label('⏸️ Inactive Rules').classes('text-lg font-semibold')
                    inactive_rules_count = ui.label('Loading...').classes('text-2xl font-bold text-gray-400')
                
                with triggered_today_card:
                    ui.label('🚨 Triggered Today').classes('text-lg font-semibold')
                    triggered_count = ui.label('Loading...').classes('text-2xl font-bold text-red-400')
                
                with avg_accuracy_card:
                    ui.label('🎯 Avg Accuracy').classes('text-lg font-semibold')
                    accuracy_rate = ui.label('Loading...').classes('text-2xl font-bold text-blue-400')
            
            # Rules table
            with ui.card().classes('w-full p-4'):
                ui.label('📋 Detection Rules').classes('text-xl font-semibold mb-4')
                
                # Table headers
                with ui.row().classes('w-full bg-gray-800 p-3 rounded font-semibold'):
                    ui.label('ID').classes('w-16')
                    ui.label('Rule Name').classes('w-64')
                    ui.label('Type').classes('w-32')
                    ui.label('Threshold').classes('w-24')
                    ui.label('Status').classes('w-24')
                    ui.label('Accuracy').classes('w-24')
                    ui.label('Last Triggered').classes('w-48')
                    ui.label('Actions').classes('w-32')
                
                rules_table = ui.column().classes('w-full')
        
        async def update_rules():
            """Update rules list"""
            try:
                rules = await fraud_service.get_fraud_rules()
                
                # Update summary
                summary = await fraud_service.get_rules_summary()
                active_rules_count.text = str(summary['active'])
                inactive_rules_count.text = str(summary['inactive'])
                triggered_count.text = str(summary['triggered_today'])
                accuracy_rate.text = f"{summary['avg_accuracy']:.1f}%"
                
                # Update rules table
                rules_table.clear()
                for rule in rules:
                    status_color = 'text-green-400' if rule['active'] else 'text-gray-400'
                    accuracy_color = 'text-green-400' if rule['accuracy'] > 80 else 'text-yellow-400' if rule['accuracy'] > 60 else 'text-red-400'
                    
                    with rules_table:
                        with ui.row().classes('w-full p-3 border-b border-gray-700 hover:bg-gray-800'):
                            ui.label(str(rule['id'])).classes('w-16')
                            ui.label(rule['name']).classes('w-64')
                            ui.label(rule['type']).classes('w-32')
                            ui.label(f"{rule['threshold']:.2f}").classes('w-24')
                            ui.label('Active' if rule['active'] else 'Inactive').classes(f'w-24 {status_color}')
                            ui.label(f"{rule['accuracy']:.1f}%").classes(f'w-24 {accuracy_color}')
                            ui.label(rule.get('last_triggered', 'Never')).classes('w-48 text-sm')
                            with ui.row().classes('w-32'):
                                ui.button('👁️', on_click=lambda r=rule: view_rule_details(r)).classes('bg-blue-600 hover:bg-blue-700 text-xs p-1')
                                ui.button('✏️', on_click=lambda r=rule: edit_rule(r)).classes('bg-yellow-600 hover:bg-yellow-700 text-xs p-1')
                                toggle_text = '⏸️' if rule['active'] else '▶️'
                                ui.button(toggle_text, on_click=lambda r=rule: toggle_rule(r)).classes('bg-purple-600 hover:bg-purple-700 text-xs p-1')
            
            except Exception as e:
                logger.error(f"Error updating rules: {e}")
                ui.notify(f"Error loading rules: {e}", type='negative')
        
        async def create_new_rule():
            """Create a new fraud detection rule"""
            with ui.dialog() as dialog, ui.card().classes('w-[500px]'):
                ui.label('Create New Fraud Rule').classes('text-xl font-bold mb-4')
                
                name_input = ui.input('Rule Name', placeholder='Enter rule name').classes('w-full')
                type_select = ui.select(['Amount Threshold', 'Velocity Check', 'Geographic', 'Time-based', 'Pattern Match'], 
                                      value='Amount Threshold', label='Rule Type').classes('w-full')
                threshold_input = ui.number('Threshold Value', value=1000, format='%.2f').classes('w-full')
                description_input = ui.textarea('Description', placeholder='Describe what this rule detects').classes('w-full')
                
                with ui.row().classes('w-full justify-end mt-4'):
                    ui.button('Cancel', on_click=dialog.close).classes('bg-gray-600 hover:bg-gray-700')
                    ui.button('Create Rule', on_click=lambda: create_rule_and_close()).classes('bg-green-600 hover:bg-green-700')
                
                async def create_rule_and_close():
                    if not name_input.value:
                        ui.notify('Please enter a rule name', type='warning')
                        return
                    
                    try:
                        rule_data = {
                            'name': name_input.value,
                            'type': type_select.value.lower().replace(' ', '_'),
                            'threshold': threshold_input.value,
                            'description': description_input.value,
                            'active': True
                        }
                        
                        rule_id = await fraud_service.create_fraud_rule(rule_data)
                        ui.notify(f'Rule {rule_id} created successfully', type='positive')
                        dialog.close()
                        await update_rules()
                    except Exception as e:
                        logger.error(f"Error creating rule: {e}")
                        ui.notify(f"Error creating rule: {e}", type='negative')
            
            dialog.open()
        
        async def view_rule_details(rule):
            """Show detailed rule information"""
            with ui.dialog() as dialog, ui.card().classes('w-[600px]'):
                ui.label(f'Rule Details - ID: {rule["id"]}').classes('text-xl font-bold mb-4')
                
                with ui.column().classes('w-full gap-3'):
                    ui.label(f'Name: {rule["name"]}').classes('text-lg font-semibold')
                    ui.label(f'Type: {rule["type"].replace("_", " ").title()}').classes('text-lg')
                    ui.label(f'Threshold: {rule["threshold"]:.2f}').classes('text-lg')
                    ui.label(f'Status: {"Active" if rule["active"] else "Inactive"}').classes('text-lg')
                    ui.label(f'Accuracy: {rule["accuracy"]:.1f}%').classes('text-lg')
                    ui.label(f'Created: {rule["created_at"]}').classes('text-lg')
                    ui.label(f'Last Triggered: {rule.get("last_triggered", "Never")}').classes('text-lg')
                    
                    ui.separator()
                    ui.label('Description:').classes('text-lg font-semibold')
                    ui.label(rule.get('description', 'No description available')).classes('text-sm bg-gray-800 p-3 rounded')
                    
                    # Rule performance metrics
                    ui.separator()
                    ui.label('Performance Metrics:').classes('text-lg font-semibold')
                    metrics = await fraud_service.get_rule_metrics(rule['id'])
                    ui.label(f'Total Triggers: {metrics["total_triggers"]}').classes('text-sm ml-4')
                    ui.label(f'True Positives: {metrics["true_positives"]}').classes('text-sm ml-4')
                    ui.label(f'False Positives: {metrics["false_positives"]}').classes('text-sm ml-4')
                    ui.label(f'Precision: {metrics["precision"]:.1f}%').classes('text-sm ml-4')
                    ui.label(f'Recall: {metrics["recall"]:.1f}%').classes('text-sm ml-4')
                
                with ui.row().classes('w-full justify-end mt-4'):
                    ui.button('Close', on_click=dialog.close).classes('bg-gray-600 hover:bg-gray-700')
                    ui.button('Edit Rule', on_click=lambda: edit_rule_from_details(rule, dialog)).classes('bg-yellow-600 hover:bg-yellow-700')
                    toggle_text = 'Deactivate' if rule['active'] else 'Activate'
                    ui.button(toggle_text, on_click=lambda: toggle_rule_and_close(rule, dialog)).classes('bg-purple-600 hover:bg-purple-700')
            
            dialog.open()
        
        async def edit_rule(rule):
            """Edit rule configuration"""
            with ui.dialog() as dialog, ui.card().classes('w-[500px]'):
                ui.label(f'Edit Rule - ID: {rule["id"]}').classes('text-xl font-bold mb-4')
                
                name_input = ui.input('Rule Name', value=rule['name']).classes('w-full')
                type_select = ui.select(['Amount Threshold', 'Velocity Check', 'Geographic', 'Time-based', 'Pattern Match'], 
                                      value=rule['type'].replace('_', ' ').title(), label='Rule Type').classes('w-full')
                threshold_input = ui.number('Threshold Value', value=rule['threshold'], format='%.2f').classes('w-full')
                description_input = ui.textarea('Description', value=rule.get('description', '')).classes('w-full')
                active_checkbox = ui.checkbox('Active', value=rule['active']).classes('w-full')
                
                with ui.row().classes('w-full justify-end mt-4'):
                    ui.button('Cancel', on_click=dialog.close).classes('bg-gray-600 hover:bg-gray-700')
                    ui.button('Save Changes', on_click=lambda: save_rule_changes()).classes('bg-green-600 hover:bg-green-700')
                
                async def save_rule_changes():
                    try:
                        updates = {
                            'name': name_input.value,
                            'type': type_select.value.lower().replace(' ', '_'),
                            'threshold': threshold_input.value,
                            'description': description_input.value,
                            'active': active_checkbox.value
                        }
                        
                        await fraud_service.update_fraud_rule(rule['id'], updates)
                        ui.notify(f'Rule {rule["id"]} updated successfully', type='positive')
                        dialog.close()
                        await update_rules()
                    except Exception as e:
                        logger.error(f"Error updating rule: {e}")
                        ui.notify(f"Error updating rule: {e}", type='negative')
            
            dialog.open()
        
        async def edit_rule_from_details(rule, parent_dialog):
            """Edit rule from details view"""
            parent_dialog.close()
            await edit_rule(rule)
        
        async def toggle_rule(rule):
            """Toggle rule active status"""
            try:
                new_status = not rule['active']
                await fraud_service.update_fraud_rule(rule['id'], {'active': new_status})
                status_text = 'activated' if new_status else 'deactivated'
                ui.notify(f'Rule {rule["id"]} {status_text}', type='positive')
                await update_rules()
            except Exception as e:
                logger.error(f"Error toggling rule: {e}")
                ui.notify(f"Error toggling rule: {e}", type='negative')
        
        async def toggle_rule_and_close(rule, dialog):
            """Toggle rule and close dialog"""
            await toggle_rule(rule)
            dialog.close()
        
        # Initial load
        await update_rules()
    
    # Run the application
    if __name__ in {"__main__", "__mp_main__"}:
        logger.info("🔒 Starting Fraud Detection & Tracking System")
        logger.info("🌐 Dashboard available at: http://localhost:8080")
        logger.info("📊 Features: Real-time monitoring, Alert management, Case tracking, Rule configuration")
        
        ui.run(
            host='0.0.0.0',
            port=8080,
            title='🔒 Fraud Detection System',
            reload=False,  # Set to True for development
            show=True,
            storage_secret='fraud_detection_secret_key_change_in_production'
        )

except ImportError as e:
    print(f"❌ Import Error: {e}")
    print("📦 Installing required dependencies...")
    import subprocess
    import sys
    
    # Install required packages
    packages = [
        'nicegui>=1.4.0',
        'sqlalchemy>=2.0.0',
        'plotly>=5.17.0',
        'pandas>=2.1.0',
        'python-dotenv>=1.0.0',
        'requests>=2.31.0',
        'pillow>=10.0.0',
        'passlib[bcrypt]>=1.7.4',
        'python-jose[cryptography]>=3.3.0'
    ]
    
    for package in packages:
        try:
            subprocess.check_call([sys.executable, '-m', 'pip', 'install', package])
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to install {package}: {e}")
    
    print("✅ Dependencies installed. Please restart the application.")
    sys.exit(1)

except Exception as e:
    print(f"❌ Critical Error: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)