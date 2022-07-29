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
package org.springframework.security.boot;

import org.junit.jupiter.api.Test;
import org.springframework.security.boot.utils.UrlDomainUtils;

/**
 * TODO
 * @author 		： <a href="https://github.com/hiwepy">wandl</a>
 */

public class UrlDomainUtilsTest {

	@Test
	public void name() {
		 String url = "https://www.baidu.com/s?wd=%E6%B5%8B%E8%AF%95&rsv_spt=1&rsv_iqid=0xeb51775c000b6302&issp=1&f=8&rsv_bp=1&rsv_idx=2&ie=utf-8&tn=baiduhome_pg&rsv_enter=1&rsv_dl=tb&rsv_sug3=6&rsv_sug1=2&rsv_sug7=100&rsv_sug2=0&inputT=928&rsv_sug4=3731&target=xxx/xx";
		 UrlDomainUtils.getDomainHost(url);
		 System.err.println(UrlDomainUtils.parseURLParams(url));
		 System.err.println(UrlDomainUtils.parseURLParam(url, "targetxx"));
	}

}
