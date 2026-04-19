import { AttackPattern, testStix, version } from '../index';

console.log('Testing stixflayer Node.js bindings...\n');

console.log('1. version():', version());
console.log('2. testStix():', testStix());

const attackPattern = new AttackPattern('Spear Phishing');
console.log('3. Created AttackPattern:', attackPattern.getType());
console.log('4. toJson():', attackPattern.toJson());

console.log('\n✅ All tests passed!');