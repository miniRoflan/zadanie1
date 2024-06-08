package org.example;

import org.jsoup.*;
import org.jsoup.nodes.Document;
import org.jsoup.select.Elements;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.*;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

class TraceASUtil {

    private static final Pattern reIP = Pattern.compile("\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}");
    private static final Pattern reAS = Pattern.compile("[Oo]riginA?S?: [AS]\\S*");
    private static final Pattern reCountry = Pattern.compile("[Cc]ountry: \\S*");
    private static final Pattern reProvider = Pattern.compile("mnt-by: \\w*");

    String tracert = "tracert";
    List<String> list = new ArrayList();

    public void TraceAS(String ip) {
        tracert = tracert + " " + ip;
        System.out.println("Executive command: " + tracert);
        try {
            command(tracert);
            for (String s : list) {
                System.out.println(s);
            }
        } catch (IOException exception) {
            exception.printStackTrace();
        }
    }

    private void command(String tracerCommand) throws IOException {
        Process process = Runtime.getRuntime().exec(tracerCommand);
        readResult(process.getInputStream());
        process.destroy();
    }

    private static String parse(String site, Pattern reg) {
        Matcher matcher = reg.matcher(site);
        if (matcher.find()) {
            return matcher.group();
        }
        return "_";
    }

    private static boolean isGreyIp(String ip) {
        return ip.startsWith("192.168.") || ip.startsWith("10.") || (ip.startsWith("172.") && 15 < Integer.parseInt(ip.split("\\.")[1]) && Integer.parseInt(ip.split("\\.")[1]) < 32);
    }

    private void readResult(InputStream inputStream) throws IOException {
        String commandInfo = null;
        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream));
        int n = 0;
        commandInfo = bufferedReader.readLine();
        while ((commandInfo = bufferedReader.readLine()) != null) {
            Matcher matcher = reIP.matcher(commandInfo);
            if (matcher.find()) {
                String ip = matcher.group();
                if (isGreyIp(ip))
                    list.add(n + " " + ip + " _ _ _");
                else {
                    String url = "https://www.nic.ru/whois/?searchWord=" + ip;
                    Document doc = Jsoup.connect(url).get();
                    Elements elements = doc.select("div._3U-mA._23Irb");
                    String st = elements.text();
                    list.add(n + " " + ip + " " + parse(st, reAS) + " " + parse(st, reCountry) + " " + parse(st, reProvider));
                }
                n++;
            }
        }
        bufferedReader.close();
    }
}

public class Main {
    public static void main(String[] args) {
        TraceASUtil util = new TraceASUtil();
        Scanner in = new Scanner(System.in);
        System.out.print("Input a name or ip: ");
        String s = in.next();
        util.TraceAS(s);
    }
}