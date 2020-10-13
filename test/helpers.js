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


const acceptRegex = require('..');

exports.testRegexSuccess = (source, unicode = false) => {
  test('regex is accepted', () => {
    if (!acceptRegex(source, { unicode })) {
      throw new Error(`Failed to accept RegEx: /${source}/${unicode ? 'u' : ''}`);
    }
  });
};

exports.testRegexFailure = (source, unicode = false) => {
  test('regex is not accepted', () => {
    if (acceptRegex(source, { unicode })) {
      throw new Error(`Failed to fail RegEx: /${source}/${unicode ? 'u' : ''}`);
    }
  });
};
