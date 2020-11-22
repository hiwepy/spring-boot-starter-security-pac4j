/*
 * Copyright (c) 2018, hiwepy (https://github.com/hiwepy).
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.springframework.security.boot.utils;

import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class UrlDomainUtils {

    private static final Logger LOGGER = LoggerFactory.getLogger(UrlDomainUtils.class);
    /*
     * 获取主域名，即URL头
     * @param url
     * @return
     */
    public static  String getDomainHost(String url){
        String pattern = "^((http://)|(https://))?([a-zA-Z0-9]([a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?\\.)+[a-zA-Z]{2,6}(/)";

        Pattern p = Pattern.compile(pattern);
        String line = url;
        Matcher m = p.matcher(line);

        if(m.find()){
            //匹配结果
            String domain = m.group();
            LOGGER.info("解析的URL主域名是------------>{}    原始url is {}" ,domain,url);
            domain = domain.replace("https","http");
            LOGGER.info("修改解析出的URL主域名的协议成http------------>{}    原始url is {}" ,domain,url);
//            domain = domain.replace("http://","");
//            LOGGER.info("修改解析出的URL主域名后去掉协议------------>{}    原始url is {}" ,domain,url);
            return domain;
        }
        LOGGER.info("未找到的URL主域名   原始url is {}" ,url);
        return null;
    }

    
    /*
     * 获取主域名，即URL头
     * @param url
     * @return
     */
    public static Map<String, String> parseURLParams(String url) {
        Map<String, String> mapRequest = new HashMap<String, String>();

        String[] arrSplit = null;

        String strUrlParam = TruncateUrlPage(url);
        if (strUrlParam == null) {
            return mapRequest;
        }
        //每个键值为一组 
        arrSplit = strUrlParam.split("[&]");
        for (String strSplit : arrSplit) {
            String[] arrSplitEqual = null;
            arrSplitEqual = strSplit.split("[=]");

            //解析出键值
            if (arrSplitEqual.length > 1) {
                //正确解析
                mapRequest.put(arrSplitEqual[0], arrSplitEqual[1]);
                continue;
            } else {
                if (arrSplitEqual[0] != "") {
                    //只有参数没有值，不加入
                    mapRequest.put(arrSplitEqual[0], "");
                }
            }
        }
        return mapRequest;
    }
    
    /*
     * 获取主域名，即URL头
     * @param url
     * @param key url中的参数key
     * @return
     */
    public static Map<String, String> parseURLParam(String URL, String key) {
        Map<String, String> mapRequest = new HashMap<String, String>();

        String[] arrSplit = null;

        String strUrlParam = TruncateUrlPage(URL);
        if (strUrlParam == null) {
            return mapRequest;
        }
        //每个键值为一组 
        arrSplit = strUrlParam.split("[&]");
        for (String strSplit : arrSplit) {
            String[] arrSplitEqual = null;
            arrSplitEqual = strSplit.split("[=]");

            //解析出键值
            if (arrSplitEqual.length > 1) {
                //正确解析
                if(key.equals(arrSplitEqual[0])){
                    mapRequest.put(arrSplitEqual[0], arrSplitEqual[1]);
                    break;
                }
            } else {
                if (arrSplitEqual[0] != "") {
                    //只有参数没有值，不加入
                    mapRequest.put(arrSplitEqual[0], "");
                }
            }
        }
        return mapRequest;
    }

    /*
     * 截取URL中的？之后的部分
     * @param strUrl
     * @return
     */
    private static String TruncateUrlPage(String strURL) {
        String strAllParam = null;
        String[] arrSplit = null;

        strURL = strURL.trim();

        arrSplit = strURL.split("[?]");
        if (strURL.length() > 1) {
            if (arrSplit.length > 1) {
                if (arrSplit[1] != null) {
                    strAllParam = arrSplit[1];
                }
            }
        }
        return strAllParam;
    }

}