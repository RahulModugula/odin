def get_user(user_id):
    query = "SELECT * FROM users WHERE id = " + str(user_id)
    return execute_query(query)

def search_users(name):
    query = f"SELECT * FROM users WHERE name = '{name}'"
    return execute_query(query)
