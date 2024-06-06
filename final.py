from encryption_util import create_user, get_user_encrypted_data, decrypt, username_exists, delete_user
import re

def is_valid_password(password):
    # Verifica se a senha tem pelo menos 8 caracteres
    if len(password) < 8:
        return False
    # Verifica se a senha contém pelo menos uma letra maiúscula
    if not re.search(r'[A-Z]', password):
        return False
    # Verifica se a senha contém pelo menos um caractere especial
    if not re.search(r'[!@#$%^&*-_(),.?":{}|<>]', password):
        return False
    return True

def main():
    while True:
        option = input("Please choose one option: \n[1] Create user \n[2] Show encrypted and decrypted password \n[3] Delete User \n[4] EXIT \nOption: ")

        if option == "1":
            username = input("Enter username: ")
            if username_exists(username):
                print("User name alredy being used, please choose another one.")
            else:
                while True:
                    password = input("Enter password: ")
                    if is_valid_password(password):
                            break
                    else:
                        print("Password must be at least 8 characters long, contain at least one uppercase letter and one special character.")
                    
                key = create_user(username, password)
                print("User created successfully!")
                print(f"Your encryption key (save this key): {key}")

        elif option == "2":
            username = input("Please insert your username: ")
            user_data = get_user_encrypted_data(username)
            if user_data:
                key, nonce, tag, ciphertext = user_data
                print(f"Encrypted password (ciphertext): {ciphertext}")

                input_key = input("Please insert your encryption key to decrypt the password (in bytes, e.g., b'\\x00\\x01...'): ")
                try:
                    # Using ast.literal_eval for safer evaluation of input
                    import ast
                    input_key = ast.literal_eval(input_key)  # Convert string input to bytes
                    if input_key == key:
                        decrypted_password = decrypt(input_key, nonce, tag, ciphertext)
                        print(f"Decrypted password: {decrypted_password}")
                    else:
                        print("The provided key is incorrect.")
                except Exception as e:
                    print(f"Decryption failed: {e}")
            else:
                print("User not found!")

        elif option == "3":
            username = input("Please, insert your username: ")
            password = input("Please, insert your password: ")
            
            if delete_user(username, password):
                print("User deleted with success!")
                
            else:
                print("Username or password incorrect, please try again.")
            
        
        elif option == "4":
            print("Exiting the program.")
            break

        else:
            print("Invalid option. Please try again.")

if __name__ == "__main__":
    main()