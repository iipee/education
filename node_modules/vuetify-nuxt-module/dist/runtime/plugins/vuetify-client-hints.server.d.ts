import type { UnwrapNestedRefs } from 'vue';
import type { SSRClientHints } from './types.js';
import type { Plugin } from '#app';
declare const plugin: Plugin<{
    ssrClientHints: UnwrapNestedRefs<SSRClientHints>;
}>;
export default plugin;
