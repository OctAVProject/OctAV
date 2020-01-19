import pickle
from sklearn.ensemble import RandomForestClassifier
from keras.preprocessing.sequence import pad_sequences

def predict(syscall_sequence_string):
	syscall_sequence = syscall_sequence_string.split(",")
	loaded_model = pickle.load(open('random_forest_model', 'rb'))
	prediction = loaded_model.predict_proba(pad_sequences([syscall_sequence], maxlen=25077, padding='post'))
	return prediction[0][1]