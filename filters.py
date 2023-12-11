from bson import ObjectId

def format_object_id(object_id):
    if isinstance(object_id, ObjectId):
        return str(object_id)
    return object_id



