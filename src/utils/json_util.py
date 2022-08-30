from json import dumps, loads, JSONEncoder, JSONDecoder
import pickle


class PythonObjectEncoder(JSONEncoder):
    def default(self, obj):
        try:
            return {'_python_object': pickle.dumps(obj).decode('latin-1')}
        except pickle.PickleError:
            return super().default(obj)


def as_python_object(dct):
    if '_python_object' in dct:
        return pickle.loads(dct['_python_object'].encode('latin-1'))
    return dct
