package com.sailpoint.idn;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

public class util {


    public String getPropertyValue(String key) {
        Properties prop = new Properties();
        InputStream input = null;
        String value = "";

        try {

            input = new FileInputStream("account_sync.properties");

            // load a properties file
            prop.load(input);

            // get the property value and print it out

            value = prop.getProperty(key);


        } catch (Exception ex) {
            ex.printStackTrace();
        } finally {
            if (input != null) {
                try {
                    input.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
        return value;
    }

}


