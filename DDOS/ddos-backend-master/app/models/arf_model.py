import pickle
import os
from river import compose, preprocessing, drift
from river.forest import ARFClassifier as ARF

class ARFModel:
    def __init__(self, app):
        self.app = app
        self.model = self._load_model()
        
    def _load_model(self):
        model_path = os.path.join(self.app.config['MODEL_PATH'], self.app.config['ARF_MODEL'])
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"ARF model not found at {model_path}")
        
        with open(model_path, 'rb') as f:
            model = pickle.load(f)
            
        return model
    
    def predict(self, features):
        return self.model.predict_one(features)
    
    def predict_proba(self, features):
        return self.model.predict_proba_one(features)
    
    def learn(self, features, label):
        self.model.learn_one(features, label)