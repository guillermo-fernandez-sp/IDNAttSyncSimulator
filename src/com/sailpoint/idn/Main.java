// Copyright 2019 SailPoint Technologies, Inc.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.sailpoint.idn;

import com.opencsv.CSVWriter;
import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;


public class Main {

    public static void main(String[] args) throws Exception {

        String log4jConfPath = "log4j.properties";
        PropertyConfigurator.configure(log4jConfPath);
        Logger logger = Logger.getLogger(Util.class.getName());
        logger.info("Starting program...");
        System.out.println("Starting program...");

        Util u = new Util();

        File ifileIDN = new File(u.getPropertyValue("inputFileNameIDN"));
        File ifileSRC = new File(u.getPropertyValue("inputFileNameSRC"));
        File ofile = new File(u.getPropertyValue("outputFileName"));
        java.io.FileWriter fw = new FileWriter(ofile);
        CSVWriter pw = new CSVWriter(fw, ',');


        // Get attribute sync list

        List<String> attSyncList = new ArrayList<String>();

        for (int i = 1; i <= Integer.parseInt(u.getPropertyValue("attSize")); i++) {
            attSyncList.add(u.getPropertyValue("att" + i));
        }

        // Get attribute map list

        List<String> attMapList = new ArrayList<String>();

        for (String attMap : attSyncList) {
            attMapList.add(u.getPropertyValue(attMap));
        }

        // Check attributes against IDN Identity List and save column reference

        try {

            // IDN input file validation

            BufferedReader ini = new BufferedReader(new InputStreamReader(new FileInputStream(ifileIDN), StandardCharsets.UTF_8));
            String stri = ini.readLine();
            String[] idnHeaderList = stri.split(",");


            Map<String, Integer> idnHeaderMap = new HashMap<String, Integer>();

            for (String attSync : attSyncList) {
                int colNumber = 1;

                for (String hValue : idnHeaderList) {

                    if (hValue.equals(attSync)) {
                        idnHeaderMap.put(attSync, colNumber);

                    }
                    colNumber++;

                }
            }


            if (idnHeaderMap.size() != Integer.parseInt(u.getPropertyValue("attSize"))) {
                logger.error("IDN Identity list file bad formed ");
            } else {
                logger.info("IDN Identity list file seems correct. Building identity list object ...");
            }

            // SRC input file validation

            BufferedReader ins = new BufferedReader(new InputStreamReader(new FileInputStream(ifileSRC), StandardCharsets.UTF_8));
            String strs = ins.readLine();

            String[] srcHeaderList = strs.split(",");

            Map<String, Integer> srcHeaderMap = new HashMap<String, Integer>();

            for (String attSync : attMapList) {
                int colNumber = 1;

                for (String hValue : srcHeaderList) {

                    if (hValue.toUpperCase().equals(attSync.toUpperCase())) {

                        srcHeaderMap.put(attSync, colNumber);

                    } else {

                    }
                    colNumber++;

                }
            }

            if (srcHeaderMap.size() != Integer.parseInt(u.getPropertyValue("attSize"))) {
                logger.error("Source file bad formed ");
            } else {
                logger.info("Source file seems correct. Building identity list object ...");
            }


            // System.out.println(Arrays.asList(srcHeaderMap));

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


            boolean found;
            String ids = "";
            HashSet adAccounts = new HashSet();
            HashSet hidn = new HashSet();
            HashSet hids = new HashSet();

            try {

                while ((strs = ins.readLine()) != null) {
                    found = false;

                    switch (u.getPropertyValue("attKey")) {

                        // AD Source - addistinguishedname: primary attribute
                        case "addistinguishedname":

                            String[] dqstri = strs.split("\"");

                            for (int x = 0; x < dqstri.length && !found; x++) {

                                if (dqstri[x].contains("CN=")) {
                                    found = true;
                                    // Get key attribute from source list file
                                    ids = dqstri[x];
                                    hids.add(ids);
                                    dqstri[x] = dqstri[x].replace(",", ";");

                                }
                            }

                            String vline = Arrays.toString(dqstri);
                            String[] sline = vline.split(",");

                            found = false;

                            String idi = "";
                            ini = new BufferedReader(new InputStreamReader(new FileInputStream(ifileIDN), StandardCharsets.UTF_8));
                            stri = ini.readLine();

                            while ((stri = ini.readLine()) != null) {
                                String[] dqstr = stri.split("\"");

                                for (int x = 0; x < dqstr.length; x++) {
                                    if (dqstr[x].contains("CN=")) {
                                        found = true;
                                        // Get key attribute from identity list file
                                        idi = dqstr[x];
                                        hidn.add(dqstr[x]);
                                        //System.out.println("idi = " + idi);
                                        dqstr[x] = dqstr[x].replace(",", ";");

                                    }
                                }

                                String nline = Arrays.toString(dqstr);
                                String[] iline = nline.split(",");

                                if (ids.equals(idi)) {
                                    if (!adAccounts.contains(ids)) {
                                        adAccounts.add(ids);
                                        System.out.println(Arrays.asList(sline));

                                    }

                                }


                            }
                            ini.close();


                    }
                    }



            } catch (Exception e) {
                logger.error("Error reading line");
                e.printStackTrace();
            }

            System.out.println("Total: " + hids.size() + " identities in " + u.getPropertyValue("source"));
            logger.info("Total: " + hids.size() + " identities in " + u.getPropertyValue("source"));

            System.out.println("Total: " + hidn.size() + " identities in IDN with attribute: " + u.getPropertyValue("attKey") + " provisioned");
            logger.info("Total: " + hidn.size() + " identities in IDN with attribute: " + u.getPropertyValue("attKey") + " provisioned");

            System.out.println("Total: " + adAccounts.size() + " matches");
            logger.info("Total: " + adAccounts.size() + " matches");

            pw.close();
            ini.close();
            ins.close();
        } catch (UnsupportedEncodingException e) {
            logger.error("Unable to read file");
            logger.error(e.getMessage());
            e.printStackTrace();
        } catch (IOException e) {
            logger.error("Unable to read file");
            logger.error(e.getMessage());
            e.printStackTrace();
        } catch (Exception e) {
            logger.error("Unable to read file");
            logger.error(e.getMessage());
            e.printStackTrace();
        }


    }


}
