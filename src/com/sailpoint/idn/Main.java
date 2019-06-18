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
        Util u = new Util();
        File ifileIDN = new File(u.getPropertyValue("inputFileNameIDN"));
        File ifileSRC = new File(u.getPropertyValue("inputFileNameSRC"));
        File ofile = new File(u.getPropertyValue("outputFileName"));
        java.io.FileWriter fw = new FileWriter(ofile);
        CSVWriter pw = new CSVWriter(fw, ',');
        List<String> attSyncList = new ArrayList<String>();
        List<String> attMapList = new ArrayList<String>();

        logger.info("Starting program...");
        System.out.println("Starting program...");

        for (int i = 1; i <= Integer.parseInt(u.getPropertyValue("attSize")); i++) {
            attSyncList.add(u.getPropertyValue("att" + i));
        }

        for (String attMap : attSyncList) {
            attMapList.add(u.getPropertyValue(attMap));
        }

        try {

            BufferedReader ini = new BufferedReader(new InputStreamReader(new FileInputStream(ifileIDN), StandardCharsets.UTF_8));
            String stri = ini.readLine();
            String[] idnHeaderList = stri.split(",");
            Map<String, Integer> idnHeaderMap = new HashMap<String, Integer>();

            for (String attSync : attSyncList) {
                int colNumber = 0;
                for (String hValue : idnHeaderList) {
                    if (hValue.contains(attSync)) {
                        idnHeaderMap.put(attSync, colNumber);

                    }
                    colNumber++;
                }
            }

            if (idnHeaderMap.size() != Integer.parseInt(u.getPropertyValue("attSize"))) {
                logger.error("Cannot read " + u.getPropertyValue("inputFileNameIDN"));
            } else {
                logger.info("IdentityNow file seems correct ...");
            }

            BufferedReader ins = new BufferedReader(new InputStreamReader(new FileInputStream(ifileSRC), StandardCharsets.UTF_8));
            String strs = ins.readLine();
            String[] srcHeaderList = strs.split(",");
            Map<String, Integer> srcHeaderMap = new HashMap<String, Integer>();

            for (String attSync : attMapList) {
                int colNumber = 0;
                for (String hValue : srcHeaderList) {
                    if (hValue.toUpperCase().equals(attSync.toUpperCase())) {
                        srcHeaderMap.put(attSync, colNumber);
                    }
                    colNumber++;
                }
            }

            if (srcHeaderMap.size() < Integer.parseInt(u.getPropertyValue("attSize"))) {
                logger.error("Cannot read " + u.getPropertyValue("inputFileNameSRC"));
            } else {
                logger.info(u.getPropertyValue("source") + " accounts file seems correct ...");
            }

            boolean found;
            String ids = "";
            HashSet adAccounts = new HashSet();
            HashSet<String> hidn = new HashSet();
            HashSet<String> hids = new HashSet();
            List<String> matches = new ArrayList<String>();
            int sycAttributes = 0;
            String outputFileHeader = "DN,AttributeName," + "IdentityNowValue," + u.getPropertyValue("source") + "Value";
            pw.writeNext(outputFileHeader.split(","));
            String outputFileContent = "";


            // Get Account List



            try {

                while ((strs = ins.readLine()) != null) {
                    found = false;

                    switch (u.getPropertyValue("source")) {

                        case "Active Directory":

                            boolean in = false;
                            StringBuilder strsb = new StringBuilder(strs);

                            for (int z = 0; z < strsb.length(); z++) {
                                if (strsb.charAt(z) == '\"' && !in) {
                                    in = true;
                                } else if (strsb.charAt(z) == '\"' && in) {
                                    in = false;
                                } else if (strsb.charAt(z) == ',' && in) {
                                    strsb.setCharAt(z, ';');
                                }
                                if (strsb.charAt(z) == '\n' && in) {
                                    strsb.setCharAt(z, ' ');
                                }
                            }

                            strs = strsb.toString().replaceAll("\"", "");
                            String[] dqstri = strs.split(",");
                            List<Integer> dnRef = new ArrayList<Integer>();

                            if (u.getPropertyValue("attKey").equals("addistinguishedname")) {

                                for (int x = 0; x < dqstri.length && !found; x++) {
                                    if (dqstri[x].contains("CN=") && !found) {
                                        found = true;
                                        dnRef.add(x);
                                        // Get key attribute from source list file
                                        ids = dqstri[x];
                                        hids.add(ids);

                                    }
                                }

                            } else {
                                if (dqstri.length > srcHeaderMap.get(u.getPropertyValue("attKey"))) {
                                    ids = dqstri[srcHeaderMap.get(u.getPropertyValue("attKey"))];
                                    if (ids.length() > 0) {
                                        hids.add(ids);
                                        System.out.println(u.getPropertyValue("attKey") + " IDS = " + ids);
                                        logger.debug(u.getPropertyValue("attKey") + " IDS = " + ids);
                                    }
                                }
                            }

                    }

                }

            } catch (Exception e) {
                logger.error("Error reading line");
                e.printStackTrace();
            }

            // Get IDN list

            try {

                String idi = "";
                ini = new BufferedReader(new InputStreamReader(new FileInputStream(ifileIDN), StandardCharsets.UTF_8));
                stri = ini.readLine();

                while ((stri = ini.readLine()) != null) {
                    boolean is = false;
                    StringBuilder strsi = new StringBuilder(stri);

                    for (int z = 0; z < strsi.length(); z++) {
                        if (strsi.charAt(z) == '\"' && !is) {
                            is = true;
                        } else if (strsi.charAt(z) == '\"' && is) {
                            is = false;
                        } else if (strsi.charAt(z) == ',' && is) {
                            strsi.setCharAt(z, ';');
                        } else if (strsi.charAt(z) == '\n' && is) {
                            strsi.setCharAt(z, ' ');
                        }
                    }

                    strs = strsi.toString().replaceAll("\"", "");
                    String[] dqstr = strs.split(",", -1);

                    if (u.getPropertyValue("attKey").equals("addistinguishedname")) {
                        for (int x = 0; x < dqstr.length; x++) {
                            if (dqstr[x].contains("CN=")) {
                                found = true;
                                idi = dqstr[x];
                                hidn.add(dqstr[x]);
                                break;

                            }
                        }
                    } else {
                        idi = dqstr[idnHeaderMap.get(u.getPropertyValue("attKeyMap"))];
                        if (idi.length() > 0) {
                            hidn.add(idi);
                            System.out.println(u.getPropertyValue("attKey") + " IDI = " + idi);
                            logger.debug(u.getPropertyValue("attKey") + " IDI = " + idi);
                        }

                    }

                }

            } catch (Exception e) {
                logger.error("Error reading line");
                e.printStackTrace();
            }

            // Correlate acounts

            for (String id : hids) {
                if (hidn.contains(id) && ids.length() > 0) {
                    System.out.println("Match = " + id);
                    matches.add(id);
                }
            }


            ins.close();
            ini.close();


            // Attribute sync

            ins = new BufferedReader(new InputStreamReader(new FileInputStream(ifileSRC), StandardCharsets.UTF_8));
            strs = ins.readLine();

            try {

                while ((strs = ins.readLine()) != null) {
                    found = false;

                    switch (u.getPropertyValue("source")) {

                        case "Active Directory":

                            boolean in = false;
                            StringBuilder strsb = new StringBuilder(strs);

                            for (int z = 0; z < strsb.length(); z++) {
                                if (strsb.charAt(z) == '\"' && !in) {
                                    in = true;
                                } else if (strsb.charAt(z) == '\"' && in) {
                                    in = false;
                                } else if (strsb.charAt(z) == ',' && in) {
                                    strsb.setCharAt(z, ';');
                                }
                                if (strsb.charAt(z) == '\n' && in) {
                                    strsb.setCharAt(z, ' ');
                                }
                            }

                            strs = strsb.toString().replaceAll("\"", "");
                            String[] dqstri = strs.split(",");
                            List<Integer> dnRef = new ArrayList<Integer>();

                            if (u.getPropertyValue("attKey").equals("addistinguishedname")) {

                                for (int x = 0; x < dqstri.length && !found; x++) {
                                    if (dqstri[x].contains("CN=") && !found) {
                                        found = true;
                                        dnRef.add(x);
                                        // Get key attribute from source list file
                                        ids = dqstri[x];
                                        hids.add(ids);
                                        break;

                                    }
                                }
                            } else {
                                if (dqstri.length > srcHeaderMap.get(u.getPropertyValue("attKey"))) {
                                    ids = dqstri[srcHeaderMap.get(u.getPropertyValue("attKey"))];

                                    if (ids.length() > 0 && !hids.contains(ids)) {
                                        hids.add(ids);
                                        System.out.println(u.getPropertyValue("attKey") + " IDS = " + ids);
                                        System.out.println(hids.toString());
                                        logger.debug(u.getPropertyValue("attKey") + " IDS = " + ids);
                                    }
                                }
                            }


                            String vline = Arrays.toString(dqstri);
                            String[] sline = vline.split(",", -1);
                            found = false;
                            String idi = "";

                            ini = new BufferedReader(new InputStreamReader(new FileInputStream(ifileIDN), StandardCharsets.UTF_8));
                            stri = ini.readLine();


                            while ((stri = ini.readLine()) != null && ids.length() > 0 && matches.contains(ids)) {
                                boolean is = false;
                                StringBuilder strsi = new StringBuilder(stri);

                                for (int z = 0; z < strsi.length(); z++) {
                                    if (strsi.charAt(z) == '\"' && !is) {
                                        is = true;
                                    } else if (strsi.charAt(z) == '\"' && is) {
                                        is = false;
                                    } else if (strsi.charAt(z) == ',' && is) {
                                        strsi.setCharAt(z, ';');
                                    } else if (strsi.charAt(z) == '\n' && is) {
                                        strsi.setCharAt(z, ' ');
                                    }
                                }

                                strs = strsi.toString().replaceAll("\"", "");
                                String[] dqstr = strs.split(",", -1);

                                if (u.getPropertyValue("attKey").equals("addistinguishedname")) {
                                    for (int x = 0; x < dqstr.length; x++) {
                                        if (dqstr[x].contains("CN=")) {
                                            found = true;
                                            idi = dqstr[x];
                                            hidn.add(dqstr[x]);
                                            break;
                                        }
                                    }
                                } else {
                                    if (dqstri.length > idnHeaderMap.get(u.getPropertyValue("attKeyMap")) && dqstr[idnHeaderMap.get(u.getPropertyValue("attKeyMap"))].length() > 0) {
                                        idi = dqstr[idnHeaderMap.get(u.getPropertyValue("attKeyMap"))];
                                        hidn.add(idi);
                                        System.out.println("IDI = " + idi);
                                        System.out.println(hidn.toString());
                                        System.out.println("HIDN ASIZE " + hidn.size());
                                    }


                                }


                                if (ids.equals(idi) && ids.length() > 0 && idi.length() > 0) {

                                    if (!adAccounts.contains(ids)) {
                                        adAccounts.add(ids);
                                        for (Map.Entry<String, Integer> entry : idnHeaderMap.entrySet()) {
                                            if (dqstr[entry.getValue()].equals(" ")) {
                                                dqstr[entry.getValue()] = dqstr[entry.getValue()].replaceAll(" ", "");
                                            } else if (dqstr[entry.getValue()].length() > 0 && dqstr[entry.getValue()].charAt(0) == ' ') {
                                                dqstr[entry.getValue()] = dqstr[entry.getValue()].substring(0, 1) + dqstr[entry.getValue()].substring(1);

                                            }
                                            if (sline[srcHeaderMap.get(u.getPropertyValue(entry.getKey()))].equals(" ")) {
                                                sline[srcHeaderMap.get(u.getPropertyValue(entry.getKey()))] =
                                                        sline[srcHeaderMap.get(u.getPropertyValue(entry.getKey()))].replace(" ", "");
                                            } else if (sline[srcHeaderMap.get(u.getPropertyValue(entry.getKey()))].length() > 0
                                                    && sline[srcHeaderMap.get(u.getPropertyValue(entry.getKey()))].charAt(0) == ' ') {

                                                sline[srcHeaderMap.get(u.getPropertyValue(entry.getKey()))] =
                                                        sline[srcHeaderMap.get(u.getPropertyValue(entry.getKey()))].replaceFirst("\\s", "");


                                            }

                                            if (!dqstr[entry.getValue()].equals(sline[srcHeaderMap.get(u.getPropertyValue(entry.getKey()))])) {
                                                sycAttributes++;
                                                outputFileContent = ids.replaceAll(",", "") + "," + entry.getKey()
                                                        + "," + dqstr[entry.getValue()] + "," + sline[srcHeaderMap.get(u.getPropertyValue(entry.getKey()))];
                                                pw.writeNext(outputFileContent.split(","));
                                                logger.info("--------------------------------------------");
                                                logger.info("Attribute value mismatch");
                                                logger.info("Attribute Name: " + entry.getKey());
                                                logger.info("Source: " + u.getPropertyValue("source"));
                                                logger.debug("Value in IdentityNow: " + dqstr[entry.getValue()]);
                                                logger.debug("Value in " + u.getPropertyValue("source") + ": " + sline[srcHeaderMap.get(u.getPropertyValue(entry.getKey()))]);
                                                logger.debug("Identity DN: " + ids.replaceAll(";", ""));
                                            }
                                        }
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


            logger.info("--------------------------------------------");

            System.out.println("Total: " + hids.size() + " identities in " + u.getPropertyValue("source"));
            logger.info("Total: " + hids.size() + " identities in " + u.getPropertyValue("source"));

            System.out.println("Total: " + hidn.size() + " identities in IdentityNow with attribute: " + u.getPropertyValue("attKey") + " provisioned");
            logger.info("Total: " + hidn.size() + " identities in IdentityNow with attribute: " + u.getPropertyValue("attKey") + " provisioned");

            System.out.println("Total: " + matches.size() + " " + u.getPropertyValue("source") + " accounts found in IdentityNow");
            logger.info("Total: " + matches.size() + " " + u.getPropertyValue("source") + " accounts found in IdentityNow");

            System.out.println("Total: " + sycAttributes + " attributes will be synchronized");
            logger.info("Total: " + sycAttributes + " attributes will be synchronized");

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
