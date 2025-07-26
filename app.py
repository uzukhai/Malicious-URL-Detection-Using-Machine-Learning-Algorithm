from flask import Flask, render_template, request
import subprocess
import time

app = Flask(__name__)

@app.route('/')
def home():
    #return "Hello, Flask!"
    return render_template('index.html')

@app.route('/your results', methods=['POST'])
def results():
    user_input = request.form['user_input']
    start_time = time.time()
    prediction = subprocess.run(
        ['python', 'predict.py', user_input],
        capture_output=True,
        text=True
    )
    end_time = time.time()
    elapsed_time = end_time - start_time
    minutes, seconds = divmod(elapsed_time, 60)
    return render_template('results.html', input=user_input, prediction=prediction.stdout.strip(), seconds=seconds)

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True, port=8080)