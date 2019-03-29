from flask import Flask, render_template, request
from Feature_generator import calculate_features
import numpy as np
from Pharming import pharming
from keras.models import load_model
from sklearn.externals import joblib
import keras.models
from keras.models import model_from_json
#from scipy.misc import imread, imresize,imshow
import tensorflow as tf

app = Flask(__name__)
app.config['DEBUG'] = True

def init(): 
	json_file = open('model1.json','r')
	loaded_model_json = json_file.read()
	json_file.close()
	loaded_model = model_from_json(loaded_model_json)
	#load woeights into new model
	loaded_model.load_weights("model1.h5")
	print("Loaded Model from disk")

	#compile and evaluate loaded model
	loaded_model.compile(loss='binary_crossentropy',optimizer='adam',metrics=['accuracy'])
	#loss,accuracy = model.evaluate(X_test,y_test)
	#print('loss:', loss)
	#print('accuracy:', accuracy)
	graph = tf.get_default_graph()

	return loaded_model,graph


global classifier, sc, graph
sc = joblib.load('scaler.save')
classifier,graph = init()


@app.route('/')
def index():
	return render_template('app_home.html')

@app.route('/predict', methods = ['POST','GET'])
def predict():
	val = request.form.get('url')
	url = str(val)
	features = calculate_features(url)
	new_features = []
	# for links_pointing
	if features[12] == -1:
		new_features.append(0.0)
		new_features.append(0.0)
	elif features[12] == 1:
		new_features.append(1.0)
		new_features.append(0.0)
	else:
		new_features.append(0.0)
		new_features.append(1.0)
	#for SFH
	if features[10] == -1:
		new_features.append(0.0)
		new_features.append(0.0)
	elif features[10] == 0:
		new_features.append(1.0)
		new_features.append(0.0)
	else:
		new_features.append(0.0)
		new_features.append(1.0)
		#forSSL
	if features[9] == -1:
		new_features.append(0.0)
		new_features.append(0.0)
	elif features[9] == 0:
		new_features.append(1.0)
		new_features.append(0.0)
	else:
		new_features.append(0.0)
		new_features.append(1.0)
	del features[12]
	del features[10]
	del features[9]
	new_features = new_features+features
	new_features = [float(i) for i in new_features]
	with graph.as_default():
		#perform the prediction
		ans = classifier.predict(sc.transform(np.array([new_features])))
	output = ''
	if ans <= 0.5:
		res = pharming(url)
		if res == 1:
			output = 'Legitimate'
		elif res == 0:
			output = 'Suspicious'
		else:
			output = 'Phishy'
	else:
		output = 'Phishy'
	#return '<h1>{}</h1>'.format(output)
	return output#render_template('app_home.html',res=output)