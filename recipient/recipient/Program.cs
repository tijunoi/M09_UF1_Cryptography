using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Xml.Serialization;
using System.Runtime.Serialization.Formatters.Binary;
using MessageEncryptedNS;
using static SerializingUtils.SerializingUtils;

namespace recipient
{
    class Program
    {
        //Atributs de Sockets
        private static IPAddress ServerIP;
        private static int PortIP;
        private static IPEndPoint ServerEndPoint;
        private static NetworkStream ClientNS;

        //Criptografia
        static RSACryptoServiceProvider RSARecipient = new RSACryptoServiceProvider();
        static MessageEncryptedClass MsgEncrypted = new MessageEncryptedClass();
        static RSAParameters PublicKey;
        static RSAParameters SenderPublicKey;

        static MessageEncryptedClass receivedEncriptedMessage;

        static void Main(string[] args)
        {
			ConnectToServer();
			
            EnviarClauPublica();
            RepClauPublica();

            ReceiveEncryptedMessage();
            DesxifrarMissatge();

            Console.ReadLine();     
        }

		//Connecta amb el servidor i actualitzar la variable ClientNS
		static void ConnectToServer()
		{
            PortIP = 11000;
            ServerIP = IPAddress.Parse("127.0.0.1");
            ServerEndPoint = new IPEndPoint(ServerIP, PortIP);

            TcpClient Client = new TcpClient();

            Client.Connect(ServerEndPoint);
            ClientNS = Client.GetStream();

		}
		
		//Envia la clau pública a l'emissor
        static void EnviarClauPublica()
        {
            PublicKey = RSARecipient.ExportParameters(false);
            byte[] publicKeyBytes = Serialize(PublicKey);

            ClientNS.Write(publicKeyBytes, 0, publicKeyBytes.Length);
        }

		//Rep la clau pública de l'emissor
        static void RepClauPublica()
        {
            byte[] bufferLocal = new byte[1024];

            int bytesRebuts = ClientNS.Read(bufferLocal, 0, bufferLocal.Length);

           SenderPublicKey = (RSAParameters) Deserialize(bufferLocal);
        }

		//Rep el missatge encriptat
        static void ReceiveEncryptedMessage()
        {
            byte[] bufferLocal = new byte[1024];

            int bytesRebuts = ClientNS.Read(bufferLocal, 0, bufferLocal.Length);

            receivedEncriptedMessage = (MessageEncryptedClass) Deserialize(bufferLocal);
        }

		//Desxifra el missatge
        static void DesxifrarMissatge()
        {
            RSACryptoServiceProvider RSASender = new RSACryptoServiceProvider();
            RSASender.ImportParameters(SenderPublicKey);



            //1. Desencripta la clau simètrica (key + IV)
            byte[] DecryptedIVBytes = RSARecipient.Decrypt(receivedEncriptedMessage.EncryptedIV, true);
            byte[] DecryptedKey = RSARecipient.Decrypt(receivedEncriptedMessage.EncryptedKey, true);


            //2. Desencriptem el missatge
            var aes = new AesCryptoServiceProvider();
            aes.IV = DecryptedIVBytes;
            aes.Key = DecryptedKey;

            byte[] msgDecryptedBytes = aes.CreateDecryptor().TransformFinalBlock(receivedEncriptedMessage.EncryptedMsg, 0, receivedEncriptedMessage.EncryptedMsg.Length);
            String mensajeDesencriptado = Encoding.UTF8.GetString(msgDecryptedBytes);

            //3. Comprovació de la integritat.
            if (RSASender.VerifyData(msgDecryptedBytes, new SHA1CryptoServiceProvider(), receivedEncriptedMessage.SignedHash))
            {
                Console.WriteLine("EL MISSATGE ES VERIDIC!!!");
                Console.WriteLine(mensajeDesencriptado);
            } else
            {
                Console.WriteLine("ERROR DE SEGURETAT!");
            }



        }

        static string BytesToStringHex(byte[] result)
        {
            StringBuilder stringBuilder = new StringBuilder();

            foreach (byte b in result)
                stringBuilder.AppendFormat("{0:x2}", b);

            return stringBuilder.ToString();
        }
    }
}
