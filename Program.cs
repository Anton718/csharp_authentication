using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using System.Security.Cryptography;

namespace csharp_auth;

class Program
{
    static string pathname = "/home/user/Desktop/Projects/csharp_authentication/data/";
    class Database
    {

        public void createDatabase(string users)
        {
            if (!File.Exists(pathname + users))
            {
                File.Create(pathname + users).Close();
                Console.WriteLine("database created");
            }
            else
            {
                Console.WriteLine("database exists");
            }
        }
    }

    class LoginInterface
    {
        public string? name;
        public string? pass;
        public void loginUser()
        {
            Console.WriteLine("Login existing user");
            Console.WriteLine("--------------------");
            Console.Write("Username: ");
            name = Console.ReadLine();
            Console.Write("Password: ");
            pass = Console.ReadLine();
        }
    }

    class RegisterInterface
    {
        public string? name;
        public string? pass;
        public void regUser()
        {
            Console.WriteLine("Register new user");
            Console.WriteLine("--------------------");
            Console.Write("Username: ");
            name = Console.ReadLine() ?? "username not provided";
            Console.Write("Password: ");
            pass = Console.ReadLine() ?? "password not provided";
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

            if (username == "" || password == "")
            {
                Console.WriteLine("Username and password cannot be empty");
                Environment.Exit(1);
            }
            string allUsers = File.ReadAllText(pathname + users);
            string[] allUsersArray = allUsers.Split(',');
            foreach (string userItem in allUsersArray)
            {
                if (!userItem.Equals(""))
                {
                    string[] userItemArray = userItem.Split(':');
                    if (userItemArray[0].Equals(username))
                    {
                        Console.WriteLine("Username already exists in database");
                        Environment.Exit(1);
                    }
                }
            }


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
            File.AppendAllText(pathname + users, username + ":" + hashed + ":" + saltToString + ",");
            Console.WriteLine("New user {0} has been created", username);
        }


        public void loginUser(string name, string pass, string users)
        {
            username = name;
            password = pass;
            string usersData = File.ReadAllText(pathname + users);
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
                    }
                    else
                    {
                        continue;
                    }
                }
                Console.WriteLine("Username or password is wrong");
                Environment.Exit(1);

            }
        }
        public void deleteUser(string name, string users)
        {
            username = name;
            string data = File.ReadAllText(pathname + users);
            string[] dataArray = data.Split(',');
            string rewrittenData = "";
            foreach (string item in dataArray)
            {
                if (item != "")
                {
                    string[] itemArray = item.Split(':');
                    if (!itemArray[0].Equals(username))
                    {
                        rewrittenData += item + ",";
                    }
                }

            }
            File.WriteAllText(pathname + users, rewrittenData);
        }
    }

    static void Main(string[] args)
    {
        Database usersDatabase = new Database();
        usersDatabase.createDatabase("users");
        User user = new User();
        RegisterInterface register = new RegisterInterface();
        LoginInterface login = new LoginInterface();
        Console.WriteLine("To register - 0, to login - 1");
        string? reply = Console.ReadLine();
        if (reply != "" && reply != null)
        {
            if (reply.Contains('0'))
            {
                register.regUser();
                if (register.name != null && register.pass != null)
                    user.registerUser(register.name, register.pass, "users");
            }
            else if (reply.Contains('1'))
            {
                login.loginUser();
                if (login.name != null && login.pass != null)
                    user.loginUser(login.name, login.pass, "users");
                Thread.Sleep(2000);
                Console.WriteLine("To del user - del");
                string response = Console.ReadLine() ?? "no input";
                if (response.Contains("del") && login.name != null)
                {
                    user.deleteUser(login.name, "users");
                    Console.WriteLine($"User {login.name} deleted");
                }
            }
        }
    }
}
