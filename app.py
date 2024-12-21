from flask import Flask, request, jsonify, render_template
import logging

app = Flask(__name__)

# Uchovávání přijatých dat
hook_data = []

# Hlavní stránka (ovládací panel)
@app.route('/')
def control_panel():
    return render_template('control_panel.html', data=hook_data)

# Endpoint pro příjem dat z JavaScript hooku
@app.route('/hook', methods=['POST'])
def receive_hook():
    try:
        data = request.json
        if data:
            hook_data.append(data)
            logging.info(f"Data received: {data}")
            return jsonify({'status': 'success', 'message': 'Data received'}), 200
        else:
            return jsonify({'status': 'error', 'message': 'No data provided'}), 400
    except Exception as e:
        logging.error(f"Error receiving data: {e}")
        return jsonify({'status': 'error', 'message': 'Internal server error'}), 500

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    app.run(host='0.0.0.0', port=5000)
