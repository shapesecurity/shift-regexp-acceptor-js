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

/* eslint-disable no-use-before-define */

import { utf16LonePropertyValues, utf16NonBinaryPropertyNames } from './unicode-properties';

import { idContinueBool, idContinueLargeRegex, idStartBool, idStartLargeRegex } from './unicode';

const syntaxCharacters = '^$\\.*+?()[]{}|'.split('');
const extendedSyntaxCharacters = '^$.*+?()[|'.split('');

const controlEscapeCharacters = 'fnrtv'.split('');
const controlEscapeCharacterValues = { 'f': '\f'.charCodeAt(0), 'n': '\n'.charCodeAt(0), 'r': '\r'.charCodeAt(0), 't': '\t'.charCodeAt(0), 'v': '\v'.charCodeAt(0) };

const controlCharacters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'.split('');
const hexDigits = '0123456789abcdefABCDEF'.split('');
const decimalDigits = '0123456789'.split('');
const octalDigits = '01234567'.split('');

function isIdentifierStart(ch) {
  return ch < 128 ? idStartBool[ch] : idStartLargeRegex.test(String.fromCodePoint(ch));
}

function isIdentifierPart(ch) {
  return ch < 128 ? idContinueBool[ch] : idContinueLargeRegex.test(String.fromCodePoint(ch));
}

class PatternAcceptorState {
  constructor(pattern, unicode) {
    this.pattern = pattern;
    this.unicode = unicode;
    this.index = 0;
    this.backreferences = [];
    this.backreferenceNames = [];
    this.groupingNames = [];
    this.capturingGroups = 0;
  }

  empty() {
    return this.index >= this.pattern.length;
  }

  nextCodePoint() {
    if (this.empty()) {
      return null;
    }
    if (this.unicode) {
      return String.fromCodePoint(this.pattern.codePointAt(this.index));
    }
    return this.pattern.charAt(this.index);
  }

  skipCodePoint() {
    this.index += this.nextCodePoint().length;
  }

  eat(str) {
    if (this.index + str.length > this.pattern.length || this.pattern.slice(this.index, this.index + str.length) !== str) {
      return false;
    }
    this.index += str.length;
    return true;
  }

  eatIdentifierStart() {
    let characterValue;
    let originalIndex = this.index;
    if (this.match('\\u')) {
      this.skip(1);
      characterValue = acceptUnicodeEscape(this);
      if (!characterValue.matched) {
        this.index = originalIndex;
        return null;
      }
      characterValue = characterValue.value;
    } else {
      characterValue = this.pattern.codePointAt(this.index);
      this.index += String.fromCodePoint(characterValue).length;
    }
    let character = String.fromCodePoint(characterValue);
    if (character === '_' || character === '$' || isIdentifierStart(characterValue)) {
      return character;
    }
    this.index = originalIndex;
    return null;
  }

  eatIdentifierPart() {
    let characterValue;
    let originalIndex = this.index;
    if (this.match('\\u')) {
      this.skip(1);
      characterValue = acceptUnicodeEscape(this);
      if (!characterValue.matched) {
        this.index = originalIndex;
        return null;
      }
      characterValue = characterValue.value;
    } else {
      characterValue = this.pattern.codePointAt(this.index);
      this.index += String.fromCodePoint(characterValue).length;
    }
    let character = String.fromCodePoint(characterValue);
    // ZWNJ / ZWJ
    if (character === '\u200C' || character === '\u200D' || character === '$' || isIdentifierPart(characterValue)) {
      return character;
    }
    this.index = originalIndex;
    return null;
  }

  eatAny(...strs) {
    for (let str of strs) {
      if (this.eat(str)) {
        return str;
      }
    }
    return null;
  }

  match(str) {
    return this.index + str.length <= this.pattern.length && this.pattern.slice(this.index, this.index + str.length) === str;
  }

  matchAny(...strs) {
    for (let str of strs) {
      if (this.match(str)) {
        return true;
      }
    }
    return false;
  }

  eatNaturalNumber() {
    let characters = [];
    let eatNumber = () => {
      for (let str of decimalDigits) {
        if (this.eat(str)) {
          characters.push(str);
          return true;
        }
      }
      return false;
    };
    while (eatNumber());
    return characters.length === 0 ? null : characters.join('');
  }
}

// acceptRegex
export default (pattern, { unicode = false } = {}) => {
  let state = new PatternAcceptorState(pattern, unicode);
  let accepted = acceptDisjunction(state);
  if (accepted.matched) {
    if (state.unicode) {
      for (let backreference of state.backreferences) {
        if (backreference > state.capturingGroups) {
          return false;
        }
      }
    }
    for (let backreferenceName of state.backreferenceNames) {
      if (state.groupingNames.indexOf(backreferenceName) === -1) {
        return false;
      }
    }
  }
  return accepted.matched;
};

const backtrackOnFailure = func => state => {
  let savedIndex = state.index;
  let oldBackreferences = state.backreferences.slice(0);
  let oldCapturingGroups = state.capturingGroups;
  let val = func(state);
  if (!val.matched) {
    state.index = savedIndex;
    state.backreferences = oldBackreferences;
    state.capturingGroups = oldCapturingGroups;
  }
  return val;
};

const acceptUnicodeEscape = backtrackOnFailure(state => {
  if (!state.eat('u')) {
    return { matched: false };
  }
  if (state.unicode && state.eat('{')) {
    let digits = [];
    while (!state.eat('}')) {
      let digit = state.eatAny(...hexDigits);
      if (digit === null) {
        return { matched: false };
      }
      digits.push(digit);
    }
    let value = parseInt(digits.join(''), 16);
    return value > 0x10FFFF ? { matched: false } : { matched: true, value };
  }
  let digits = [0, 0, 0, 0].map(() => state.eatAny(...hexDigits));
  if (digits.some(digit => digit === null)) {
    return { matched: false };
  }
  let value = parseInt(digits.join(''), 16);
  if (state.unicode && value >= 0xD800 && value <= 0xDBFF) {
    let surrogatePairValue = backtrackOnFailure(subState => {
      if (!subState.eat('\\u')) {
        return { matched: false };
      }
      let digits2 = [0, 0, 0, 0].map(() => subState.eatAny(...hexDigits));
      if (digits2.some(digit => digit === null)) {
        return { matched: false };
      }
      let value2 = parseInt(digits2.join(''), 16);
      if (value2 < 0xDC00 || value2 >= 0xE000) {
        return { matched: false };
      }
      return { matched: true, value: 0x10000 + ((value & 0x03FF) << 10) + (value2 & 0x03FF) };
    })(state);
    if (surrogatePairValue.matched) {
      return surrogatePairValue;
    }
  }
  return { matched: true, value };
});

const acceptDisjunction = (state, terminator) => {
  do {
    if (terminator !== void 0 && state.eat(terminator)) {
      return { matched: true };
    } else if (state.match('|')) {
      continue;
    }
    if (!acceptAlternative(state, terminator).matched) {
      return { matched: false };
    }
  } while (state.eat('|'));
  return { matched: terminator === void 0 || !!state.eat(terminator) };
};

const acceptAlternative = (state, terminator) => {
  while (!state.match('|') && !state.empty() && (terminator === void 0 || !state.match(terminator))) {
    if (!acceptTerm(state).matched) {
      return { matched: false };
    }
  }
  return { matched: true };
};

const anyOf = (...acceptors) => state => {
  for (let predicate of acceptors) {
    let value = predicate(state);
    if (value.matched) {
      return value;
    }
  }
  return { matched: false };
};

const acceptTerm = state => {
  // non-quantified references are rolled into quantified accepts to improve performance significantly.
  if (state.unicode) {
    return anyOf(acceptAssertion, acceptQuantified(acceptAtom))(state);
  }
  return anyOf(acceptQuantified(acceptQuantifiableAssertion),
    acceptAssertion,
    acceptQuantified(acceptAtom))(state);
};

const acceptLabeledGroup = predicate => backtrackOnFailure(state => {
  if (!state.eat('(')) {
    return { matched: false };
  }
  if (predicate(state)) {
    return acceptDisjunction(state, ')');
  }
  return { matched: false };
});

const acceptQuantifiableAssertion = acceptLabeledGroup(state => !!state.eatAny('?=', '?!'));

const acceptAssertion = state => {
  if (state.eatAny('^', '$', '\\b', '\\B')) {
    return { matched: true };
  }
  return acceptLabeledGroup(subState => subState.unicode ? !!subState.eatAny('?=', '?!', '?<=', '?<!') : !!subState.eatAny('?<=', '?<!'))(state);
};

const acceptDecimal = state => {
  return { matched: state.eatNaturalNumber() !== null };
};

const acceptQuantified = acceptor => backtrackOnFailure(state => {
  if (!acceptor(state).matched) {
    return { matched: false };
  }
  if (state.match('{')) {
    let value = backtrackOnFailure(subState => {
      subState.eat('{');
      let num1 = subState.eatNaturalNumber();
      if (num1 === null) {
        return { matched: false };
      }
      if (subState.eat(',') && subState.matchAny(...decimalDigits)) {
        let num2 = subState.eatNaturalNumber();
        if (num2 === null || parseInt(num1) > parseInt(num2)) {
          return { matched: false };
        }
      }
      if (!subState.eat('}')) {
        return { matched: false };
      }
      subState.eat('?');
      return { matched: true };
    })(state);
    if (!value.matched) {
      return { matched: !state.unicode };
    }
    return value;
  } else if (state.eatAny('*', '+', '?')) {
    state.eat('?');
  }
  return { matched: true };
});

const acceptCharacterExcept = characters => state => {
  let nextCodePoint = state.nextCodePoint();
  if (nextCodePoint === null || characters.indexOf(nextCodePoint) !== -1) {
    return { matched: false };
  }
  state.skipCodePoint();
  return { matched: true };
};

const acceptPatternCharacter = acceptCharacterExcept(syntaxCharacters);

const acceptExtendedPatternCharacter = acceptCharacterExcept(extendedSyntaxCharacters);

const acceptInvalidBracedQuantifier = state => {
  return backtrackOnFailure(subState => {
    return { matched: !!(subState.eat('{') && acceptDecimal(subState).matched && (!subState.eat(',') || subState.match('}') || acceptDecimal(subState).matched) && subState.eat('}')) };
  })(state);
};

const acceptAtom = state => {
  if (state.unicode) {
    return anyOf(acceptPatternCharacter,
      subState => ({ matched: !!subState.eat('.') }),
      backtrackOnFailure(subState => subState.eat('\\') ? acceptAtomEscape(subState) : { matched: false }),
      acceptCharacterClass,
      acceptLabeledGroup(subState => subState.eat('?:')),
      acceptGrouping)(state);
  }
  let matched = anyOf(
    subState => ({ matched: !!subState.eat('.') }),
    backtrackOnFailure(subState => subState.eat('\\') ? acceptAtomEscape(subState) : { matched: false }),
    backtrackOnFailure(subState => ({ matched: subState.eat('\\') && subState.match('c') })),
    acceptCharacterClass,
    acceptLabeledGroup(subState => subState.eat('?:')),
    acceptGrouping)(state);
  if (!matched.matched && acceptInvalidBracedQuantifier(state).matched) {
    return { matched: false };
  }
  return matched.matched ? matched : acceptExtendedPatternCharacter(state);

};

const acceptGrouping = backtrackOnFailure(state => {
  if (!state.eat('(')) {
    return { matched: false };
  }
  let groupName = backtrackOnFailure(subState => {
    if (!state.eat('?')) {
      return { matched: false };
    }
    return acceptGroupName(subState);
  })(state);
  if (!acceptDisjunction(state, ')').matched) {
    return { matched: false };
  }
  if (groupName.matched) {
    if (state.groupingNames.indexOf(groupName.data) !== -1) {
      return { matched: false };
    }
    state.groupingNames.push(groupName.data);
  }
  state.capturingGroups++;
  return { matched: true };
});

const acceptDecimalEscape = backtrackOnFailure(state => {
  let firstDecimal = state.eatAny(...decimalDigits.slice(1));
  if (firstDecimal === null) {
    return { matched: false };
  }
  // we also accept octal escapes here, but it is impossible to tell if it is a octal escape until all parsing is complete.
  // octal escapes are handled in acceptCharacterEscape for classes
  state.backreferences.push(parseInt(firstDecimal + (state.eatNaturalNumber() || '')));
  return { matched: true };
});

const acceptCharacterClassEscape = state => {
  if (state.eatAny('d', 'D', 's', 'S', 'w', 'W')) {
    return { matched: true };
  }
  if (state.unicode) {
    return backtrackOnFailure(subState => {
      if (!subState.eat('p{') && !subState.eat('P{')) {
        return { matched: false };
      }
      if (!acceptUnicodePropertyValueExpression(subState).matched) {
        return { matched: false };
      }
      return { matched: !!subState.eat('}') };
    })(state);
  }
  return { matched: false };
};

const acceptUnicodePropertyName = state => {
  let characters = [];
  let character;
  while (character = state.eatAny(...controlCharacters, '_')) { // eslint-disable-line no-cond-assign
    characters.push(character);
  }
  return { matched: characters.length > 0, data: characters.join('') };
};

const acceptUnicodePropertyValue = state => {
  let characters = [];
  let character;
  while (character = state.eatAny(...controlCharacters, ...decimalDigits, '_')) { // eslint-disable-line no-cond-assign
    characters.push(character);
  }
  return { matched: characters.length > 0, data: characters.join('') };
};

const acceptLoneUnicodePropertyNameOrValue = state => {
  let loneValue = acceptUnicodePropertyValue(state);
  return { matched: loneValue.matched && utf16LonePropertyValues.indexOf(loneValue.data) >= 0 };
};

const acceptUnicodePropertyValueExpression = state =>
  anyOf(backtrackOnFailure(subState => {
    let name = acceptUnicodePropertyName(subState);
    if (!name.matched || !subState.eat('=')) {
      return { matched: false };
    }
    let value = acceptUnicodePropertyValue(subState);
    if (!value.matched) {
      return { matched: false };
    }
    return { matched: name.data in utf16NonBinaryPropertyNames && utf16NonBinaryPropertyNames[name.data].indexOf(value.data) >= 0 };
  }),
  backtrackOnFailure(acceptLoneUnicodePropertyNameOrValue))(state);

const acceptCharacterEscape = anyOf(
  state => {
    let eaten = state.eatAny(...controlEscapeCharacters);
    if (eaten === null) {
      return { matched: false };
    }
    return { matched: true, value: controlEscapeCharacterValues[eaten] };
  },
  backtrackOnFailure(state => {
    if (!state.eat('c')) {
      return { matched: false };
    }
    let character = state.eatAny(...controlCharacters);
    if (character === null) {
      return { matched: false };
    }
    return { matched: true, value: character.charCodeAt(0) % 32 };
  }),
  backtrackOnFailure(state => {
    if (!state.eat('0') || state.eatAny(...decimalDigits)) {
      return { matched: false };
    }
    return { matched: true, value: 0 };
  }),
  backtrackOnFailure(state => {
    if (!state.eat('x')) {
      return { matched: false };
    }
    let digits = [0, 0].map(() => state.eatAny(...hexDigits));
    if (digits.some(value => value === null)) {
      return { matched: false };
    }
    return { matched: true, value: parseInt(digits.join(''), 16) };
  }),
  acceptUnicodeEscape,
  backtrackOnFailure(state => {
    if (state.unicode) {
      return { matched: false };
    }
    let octal1 = state.eatAny(...octalDigits);
    if (octal1 === null) {
      return { matched: false };
    }
    let octal1Value = parseInt(octal1, 8);
    if (octalDigits.indexOf(state.nextCodePoint()) === -1) {
      return { matched: true, value: octal1Value };
    }
    let octal2 = state.eatAny(...octalDigits);
    let octal2Value = parseInt(octal2, 8);
    if (octal1Value < 4) {
      if (octalDigits.indexOf(state.nextCodePoint()) === -1) {
        return { matched: true, value: octal1Value << 3 | octal2Value };
      }
      let octal3 = state.eatAny(...octalDigits);
      let octal3Value = parseInt(octal3, 8);
      return { matched: true, value: octal1Value << 6 | octal2Value << 3 | octal3Value };
    }
    return { matched: true, value: octal1Value << 3 | octal2Value };
  }),
  backtrackOnFailure(state => {
    if (!state.unicode) {
      return { matched: false };
    }
    let value = state.eatAny(...syntaxCharacters);
    if (value === null) {
      return { matched: false };
    }
    return { matched: true, value: value.charCodeAt(0) };
  }),
  state => {
    if (!state.unicode || !state.eat('/')) {
      return { matched: false };
    }
    return { matched: true, value: '/'.charCodeAt(0) };
  },
  backtrackOnFailure(state => {
    if (state.unicode) {
      return { matched: false };
    }
    let next = state.nextCodePoint();
    if (next !== null && next !== 'c') {
      state.skipCodePoint();
      return { matched: true, value: next.codePointAt(0) };
    }
    return { matched: false };
  })
);

const acceptGroupNameBackreference = backtrackOnFailure(state => {
  if (!state.eat('k')) {
    return { matched: false };
  }
  let name = acceptGroupName(state);
  if (!name.matched) {
    return { matched: false };
  }
  state.backreferenceNames.push(name.data);
  return { matched: true };
});

const acceptGroupName = backtrackOnFailure(state => {
  if (!state.eat('<')) {
    return { matched: false };
  }
  let characters = [];
  let start = state.eatIdentifierStart();
  if (!start) {
    return { matched: false };
  }
  characters.push(start);
  let part;
  while (part = state.eatIdentifierPart()) { // eslint-disable-line no-cond-assign
    characters.push(part);
  }
  if (!state.eat('>')) {
    return { matched: false };
  }
  return { matched: characters.length > 0, data: characters.join('') };
});

const acceptAtomEscape = anyOf(
  acceptDecimalEscape,
  acceptCharacterClassEscape,
  acceptCharacterEscape,
  acceptGroupNameBackreference
);

const acceptCharacterClass = backtrackOnFailure(state => {
  if (!state.eat('[')) {
    return { matched: false };
  }
  state.eat('^');

  const acceptClassEscape = anyOf(
    subState => {
      return { matched: !!subState.eat('b'), value: 0x0008 };
    },
    subState => {
      if (!subState.unicode) {
        return { matched: false };
      }
      return acceptDecimalEscape(subState);
    },
    subState => {
      return { matched: subState.unicode && !!subState.eat('-'), value: '-'.charCodeAt(0) };
    },
    backtrackOnFailure(subState => {
      if (subState.unicode || !subState.eat('c')) {
        return { matched: false };
      }
      let character = subState.eatAny(...decimalDigits, '_');
      if (character === null) {
        return { matched: false };
      }
      return { matched: true, value: character.charCodeAt(0) % 32 };
    }),
    acceptCharacterClassEscape,
    acceptCharacterEscape
  );

  const acceptClassAtomNoDash = localState => {
    if (localState.match('\\')) {
      let ret = backtrackOnFailure(subState => {
        subState.eat('\\');
        return acceptClassEscape(subState);
      })(localState);
      if (ret.matched) {
        return ret;
      } else if (!localState.match('\\c') || localState.unicode) {
        return { matched: false };
      }
    }
    let nextCodePoint = localState.nextCodePoint();
    if (nextCodePoint === null || nextCodePoint === ']' || nextCodePoint === '-') {
      return { matched: false };
    }
    localState.skipCodePoint();
    return { matched: true, value: nextCodePoint.codePointAt(0) };
  };

  const acceptClassAtom = localState => {
    if (localState.eat('-')) {
      return { matched: true, value: '-'.charCodeAt(0) };
    }
    return acceptClassAtomNoDash(localState);
  };

  const finishClassRange = (localState, atom) => {
    const isUnvaluedPassedAtom = subAtom => {
      return subAtom.value === void 0 && subAtom.matched;
    };
    if (localState.eat('-')) {
      if (localState.match(']')) {
        return { matched: true };
      }
      let otherAtom = acceptClassAtom(localState);
      if (!otherAtom.matched) {
        return { matched: false };
      }
      if (localState.unicode && (isUnvaluedPassedAtom(atom) || isUnvaluedPassedAtom(otherAtom))) {
        return { matched: false };
      } else if (!(!localState.unicode && (isUnvaluedPassedAtom(atom) || isUnvaluedPassedAtom(otherAtom))) && atom.value > otherAtom.value) {
        return { matched: false };
      } else if (localState.match(']')) {
        return { matched: true };
      }
      return acceptNonEmptyClassRanges(localState);

    }
    if (localState.match(']')) {
      return { matched: true };
    }
    return acceptNonEmptyClassRangesNoDash(localState);
  };

  const acceptNonEmptyClassRanges = localState => {
    let atom = acceptClassAtom(localState);
    return atom.matched ? finishClassRange(localState, atom) : { matched: false };
  };

  const acceptNonEmptyClassRangesNoDash = localState => {
    let atom = acceptClassAtomNoDash(localState);
    return atom.matched ? finishClassRange(localState, atom) : { matched: false };
  };

  if (state.eat(']')) {
    return { matched: true };
  }

  let value = acceptNonEmptyClassRanges(state);
  if (value.matched) {
    state.eat(']'); // cannot fail, as above will not return matched if it is not seen in advance
  }

  return value;
});
