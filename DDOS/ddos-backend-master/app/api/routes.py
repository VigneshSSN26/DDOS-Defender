from flask import Blueprint, jsonify, request
from app.services.defender_service import defender

api_blueprint = Blueprint('api', __name__)

@api_blueprint.route('/status', methods=['GET'])
def get_status():
    return jsonify({
        'running': defender.running,
        'lastAction': defender.last_action,
        'currentThreat': defender.last_attack_type,
        'attackerIp': defender.current_attacker,
        'lastReward': defender.last_reward
    })

@api_blueprint.route('/traffic', methods=['GET'])
def get_traffic_stats():
    features = defender.extractor.get_features() if defender.extractor.window else None
    return jsonify({
        'packetRate': features[0] if features else 0,
        'tcpRatio': features[5]*100 if features else 0,
        'udpRatio': features[6]*100 if features else 0,
        'uniqueIps': features[10] if features else 0,
        'synRatio': features[8]*100 if features else 0
    })

@api_blueprint.route('/attack-log', methods=['GET'])
def get_attack_log():
    return jsonify(list(defender.attack_log))

@api_blueprint.route('/mitigation-log', methods=['GET'])
def get_mitigation_log():
    return jsonify(list(defender.mitigation_log))

@api_blueprint.route('/start-attack', methods=['POST'])
def start_attack():
    data = request.json
    defender.simulate_attack(data['attackType'])
    return jsonify({'success': True})

@api_blueprint.route('/stop-attack', methods=['POST'])
def stop_attack():
    defender.simulate_attack("normal")
    return jsonify({'success': True})