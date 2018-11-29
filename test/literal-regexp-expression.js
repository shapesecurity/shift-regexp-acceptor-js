/**
 * Copyright 2018 Shape Security, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License")
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import { testRegexSuccess, testRegexFailure } from './helpers';

suite('Parser', () => {

  const preprocessRegexList = str => {
    return str.split('\n')
      .map(regex => regex.trim())
      .map(regex => [regex.substring(regex.indexOf('/') + 1, regex.lastIndexOf('/')), regex.endsWith('/u')]);
  };

  suite('literal regexp expression', () => {
    const regexToPass = preprocessRegexList(String.raw`/./
      /.|./
      /.||./
      /|/
      /|.||.|/
      /^$\b\B/
      /^X/
      /X$/
      /\bX/
      /\BX/
      /(?=t|v|X|.|$||)/
      /(?!t|v|X|.|$||)/
      /(?=t|v|X|.|$||)/u
      /(?!t|v|X|.|$||)/u
      /(?=t|v|X|.|$||)*/
      /(?!t|v|X|.|$||)*/
      /X*/
      /X+/
      /X?/
      /X*?/
      /X+?/
      /X??/
      /X{5}/
      /X{5,}/
      /X{5,10}/
      /X{5}?/
      /X{5,}?/
      /X{5,10}?/
      /./
      /${'\\123'}/
      /${'\\0'}/
      /${'\\0'}/u
      /${'\\1'}()/
      /${'\\1'}()/u
      /${'\\2'}/
      /${'\\2'}()()/u
      /\d/
      /\D/
      /\s/
      /\S/
      /\w/
      /\W/
      /\d/u
      /\D/u
      /\s/u
      /\S/u
      /\w/u
      /\W/u
      /[]/
      /[^]/
      /[X]/
      /[^X]/
      /[-X]/
      /[^-X]/
      /[X-]/
      /[^X-]/
      /[0-9-a-]/
      /[^0-9-a-]/
      /[0-9-a-z]/
      /[^0-9-a-z]/
      /[0-9-a-z-]/
      /[^0-9-a-z-]/
      /[]/u
      /[^]/u
      /[X]/u
      /[^X]/u
      /[-X]/u
      /[^-X]/u
      /[X-]/u
      /[^X-]/u
      /[0-9-a-]/u
      /[^0-9-a-]/u
      /[0-9-a-z]/u
      /[^0-9-a-z]/u
      /[0-9-a-z-]/u
      /[^0-9-a-z-]/u
      /[{}[||)(()\]?+*.$^]/
      /[{}[||)(()\]?+*.$^]/u
      /[\b]/
      /[\b]/u
      /\d]/
      /[\D]/
      /[\s]/
      /[\S]/
      /[\w]/
      /[\W]/
      /\f/
      /\n/
      /\r/
      /\t/
      /\v/
      /\ca/
      /\cZ/
      /\xAA/
      /${'\\xZZ'}/
      /\x0F/
      /\u10AB/
      /\u10AB/u
      /\uD800/u
      /\uDF00/u
      /\uD800\uDF00/u
      /\u{001AD}/u
      /\u{10FFFF}/u
      /\u{0}/u
      /\L/
      /\$/
      /\$/u
      /[\s-X]/
      /{dfwfdf}/
      /{5.}/
      /{5,X}/
      /{5,10X}/
      /[\c5]/
      /[\c10]/u
      /[\${'\\5'}]/
      /(?:)/
      /(?:X)/
      /}*/
      /]*/
      /[${'\\123'}]/
      /[\_]/
      /[${'\\1'}]/
      /[${'\\9'}]/
      /[\-]/u
      /[\-]/
      /\ud800\u1000/u
      /\u{10}/u
      /[${'\\1'}]/
      /[${'\\7'}]/
      /[${'\\15'}]/
      /[${'\\153'}]/
      /[${'\\72'}]/
      /\k/
      /t{5/
      /[💩-💫]/u
      /[\u{1F4A9}-\u{1F4AB}]/u`);
    const regexToFail = preprocessRegexList(String.raw`/[/
      /(?<=t|v|X|.|$||)/
      /(?<!t|v|X|.|$||)/
      /(?<=t|v|X|.|$||)/u
      /(?<!t|v|X|.|$||)/u
      /(?=t|v|X|.|$||)*/u
      /(?!t|v|X|.|$||)*/u
      /(?<=t|v|X|.|$||)*/
      /(?<!t|v|X|.|$||)*/
      /(?<=t|v|X|.|$||)*/u
      /(?<!t|v|X|.|$||)*/u
      /X{10,5}/
      /X{10,5}?/
      /${'\\123'}/u
      /${'\\1'}/u
      /${'\\2'}/u
      /\p{ASCII}/u
      /\P{ASCII}/u
      /${'\\u'}{110FFFF}/u
      /\L/u
      /[b-a]/
      /[\s-X]/u
      /{dfwfdf}/u
      /{5,10}/
      /{5,10}/u
      /{5.}/u
      /{5,X}/u
      /{5,10X}/u
      /(?:)${'\\1'}/u
      /}*/u
      /]*/u
      /[${'\\123'}]/u
      /[\_]/u
      /[${'\\1'}]/u
      /[${'\\9'}]/u
      /\c/u
      /\k<X>/u
      /(?<X>)/u
      /\c/
      /${'\\xZZ'}/u
      /\ud800${'\\uZZ'}/u
      /${'\\uZZ'}/u
      /${'\\u'}{ZZ}/u
      /5{5,1G}/u
      /\k/u
      /[💫-💩]/u
      /[\u{1F4AB}-\u{1F4A9}]/u`);
    regexToPass.forEach(args => testRegexSuccess(...args));
    regexToFail.forEach(args => testRegexFailure(...args));
  });
});
