using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using System.Security.Cryptography;

namespace csharp_auth;

class Program
{
    class Database
    {
        public void createDatabase(string users)
        {
            if (!File.Exists(users))
            {
                File.Create(users).Close();
                Console.WriteLine("database created");
            } else {
                Console.WriteLine("database exists");
            }
        }
    }
    class User 
    {
        public string? username;
        public string? password;
  
        public void registerUser(string name, string pass, string users)
        {
            username = name;
            password = pass;
            byte[] salt = RandomNumberGenerator.GetBytes(128 / 8);
            string hashed = Convert.ToBase64String(KeyDerivation.Pbkdf2(
                password: password,
                salt: salt,
                prf: KeyDerivationPrf.HMACSHA256,
                iterationCount: 100000,
                numBytesRequested: 256 / 8)
            );
            string saltToString = "";
            foreach (byte item in salt) 
            {
                saltToString += item.ToString() + " ";
            }
            File.AppendAllText(users, username + ":" + hashed + ":" + saltToString + ",");
        }
        public void loginUser(string name , string pass, string users)
        {
            username = name;
            password = pass;
            string usersData = File.ReadAllText(users);
            string[] usersDataArray = usersData.Split(',');
            foreach (string userItem in usersDataArray)
            {
                if (!userItem.Equals(""))
                {
                    string[] userItemArray = userItem.Split(":");
                    string[] saltArray = userItemArray[2].Trim().Split(" ");
                    byte[] salt = Array.ConvertAll(saltArray, Byte.Parse);
                    string hashed = Convert.ToBase64String(KeyDerivation.Pbkdf2(
                        password: password,
                        salt: salt,
                        prf: KeyDerivationPrf.HMACSHA256,
                        iterationCount: 100000,
                        numBytesRequested: 256 / 8)
                    );
                    if (userItemArray[0].Equals(username) && userItemArray[1].Equals(hashed))
                    {
                        Console.WriteLine("You are logged in");
                        break;
                    } else {
                        continue;
                        }
                }
                    Console.WriteLine("Username or password is wrong");
            }
            
        }
    }

    class Account : User
    {
    }
    static void Main(string[] args)
    {
        Database usersDatabase = new Database();
        usersDatabase.createDatabase("users");
        User user = new User();

    }
}
