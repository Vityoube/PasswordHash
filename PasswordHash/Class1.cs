using System;
using Microsoft.SqlServer.Server;
using System.Collections;
using System.Data;
using System.Data.Sql;
using System.Data.SqlTypes;
using System.Data.SqlClient;
using System.Diagnostics;
using System.Collections.Generic;

public class PasswordHash
{
    private class Password 
    {
        public Int32? moc;
        public String hash;

        public Password(Int32? Moc, String Hash)
        {
            moc = Moc;
            hash = Hash;
        }
    }
    [SqlFunction(DataAccess = DataAccessKind.Read, FillRowMethodName = "Pobierz")]
    public static IEnumerable passwordHash(String passwordString)
    {
        List<Password> password = new List<Password>();
        if (passwordString == null || "".Equals(passwordString) )
        {
            password.Add(new Password(0, null));
        }
        else
        {
            Int32? MocHasla = 0;
            Int32? pwlength = 0;
            if (passwordString.ToString().Length >= 3)
                pwlength = 3;
            else
                pwlength = passwordString.ToString().Length;
            Int32? numeric = 0;
            Int32? numsymbols = 0;
            Int32? upper = 0;
            foreach(char symbol in passwordString)
            {
                if (Char.IsDigit(symbol))
                    numeric++;
                else if (!Char.IsLetterOrDigit(symbol) && symbol != '_')
                    numsymbols++;
                else if (Char.IsUpper(symbol))
                    upper++;
            }
            if (numeric > 3)
                numeric = 3;
            if (numsymbols > 3)
                numsymbols = 3;
            if (upper > 3)
                upper = 3;
            MocHasla = ((pwlength * 10) - 20) + (numeric * 10) + (numsymbols * 15) + (upper * 10);
            String hashedPassword = "";
            if (String.IsNullOrEmpty(passwordString))
                hashedPassword = String.Empty;

            using (var sha = new System.Security.Cryptography.SHA256Managed())
            {
                byte[] textData = System.Text.Encoding.UTF8.GetBytes(passwordString);
                byte[] hash = sha.ComputeHash(textData);
                hashedPassword=BitConverter.ToString(hash).Replace("-", String.Empty);
            }

            password.Add(new Password(MocHasla, hashedPassword));
        }
        return password;
    }


    public static void Pobierz(
           object passwordObject,
           out Int32? moc,
           out String hash)
    {
        moc = null;
        hash = null;
        Password password = (Password)passwordObject;
        moc = password.moc;
        hash = password.hash;


    }



}
