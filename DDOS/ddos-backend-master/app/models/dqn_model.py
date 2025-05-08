import torch
import torch.nn as nn
import os

class DQN(nn.Module):
    def __init__(self, state_size=25, action_size=6):
        super(DQN, self).__init__()
        self.fc1 = nn.Linear(state_size, 128)
        self.fc2 = nn.Linear(128, 128)
        self.fc3 = nn.Linear(128, action_size)
        
    def forward(self, x):
        x = torch.relu(self.fc1(x))
        x = torch.relu(self.fc2(x))
        return self.fc3(x)

class DQNModel:
    def __init__(self, app):
        self.app = app
        self.model = self._load_model()
        
    def _load_model(self):
        model_path = os.path.join(self.app.config['MODEL_PATH'], self.app.config['DQN_MODEL'])
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"DQN model not found at {model_path}")
        
        # Set device to CPU (or GPU if available)
        device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        checkpoint = torch.load(model_path, map_location=device)
        
        model = DQN(state_size=checkpoint.get('state_size', 25), action_size=checkpoint.get('action_size', 6))  # use checkpoint sizes if available

        try:
            # Attempt to load the model with strict=False to ignore mismatched layers
            model.load_state_dict(checkpoint.get('model_state_dict', checkpoint), strict=False)
        except Exception as e:
            raise ValueError(f"Error loading model state_dict: {str(e)}")
        
        # Check and print the model's state_dict to debug layer mismatches
        print("Model State Dict Keys:", model.state_dict().keys())
        print("Checkpoint Keys:", checkpoint.keys())
        
        model.to(device)  # Move model to correct device (CPU or GPU)
        model.eval()
        return model
    
    def predict(self, state):
        with torch.no_grad():
            state_tensor = torch.FloatTensor(state).unsqueeze(0)  # Ensure state is in batch dimension (1, state_size)
            q_values = self.model(state_tensor)
            return q_values.argmax().item()
