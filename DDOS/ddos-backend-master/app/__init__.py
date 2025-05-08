from flask import Flask
from flask_cors import CORS
import os
import torch
import pickle

def create_app():
    app = Flask(__name__)
    CORS(app)
    
    # Configuration
    app.config['MODEL_PATH'] = os.path.join(os.path.dirname(__file__), 'models')
    app.config['DQN_MODEL'] = 'ddos_dqn_model.pth'
    app.config['ARF_MODEL'] = 'ddos_enhanced_model.pkl'
    
    # Initialize models and services
    with app.app_context():
        from app.models.dqn_model import DQNModel
        from app.models.arf_model import ARFModel
        from app.services.defender_service import DDoSDefender
        
        # Load models
        dqn_model = DQNModel(app)
        arf_model = ARFModel(app)
        
        # Initialize defender service
        app.defender = DDoSDefender(dqn_model, arf_model)
        
        # Start monitoring in background
        from threading import Thread
        monitor_thread = Thread(target=app.defender.monitor, daemon=True)
        monitor_thread.start()
    
    # Register blueprints
    from app.api.routes import api_blueprint
    app.register_blueprint(api_blueprint, url_prefix='/api')
    
    return app