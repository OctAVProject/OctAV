import pickle
import os
from sklearn.ensemble import RandomForestClassifier
from keras.preprocessing.sequence import pad_sequences

def predict(syscall_sequence_string):
	model_file_path = "../../files"
	for filename in os.listdir(model_file_path):
		if filename.startswith('random_forest_model'):
			model_file_path += filename
			
	sequence_max_length = int(model_file_path.split("_")[-1])

	syscall_sequence = syscall_sequence_string.split(",")
	loaded_model = pickle.load(open(model_file_path, 'rb'))
	prediction = loaded_model.predict_proba(pad_sequences([syscall_sequence], maxlen=sequence_max_length, padding='post'))
	return prediction[0][1]