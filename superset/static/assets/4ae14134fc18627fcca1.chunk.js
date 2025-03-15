"use strict";(globalThis.webpackChunksuperset=globalThis.webpackChunksuperset||[]).push([[8464],{708464:(e,t,l)=>{l.r(t),l.d(t,{default:()=>c});var a=l(573126),n=l(355786),s=l(310581),u=l(61988),o=l(667294),i=l(104715),r=l(174448),h=l(211965);function c(e){var t;const{data:l,formData:c,height:d,width:v,setDataMask:g,setHoveredFilter:m,unsetHoveredFilter:p,setFocusedFilter:f,unsetFocusedFilter:b,setFilterActive:w,filterState:F,inputRef:S}=e,{defaultValue:Z,multiSelect:k}=c,[C,M]=(0,o.useState)(null!=Z?Z:[]),x=e=>{const t=(0,n.Z)(e);M(t);const l={};t.length&&(l.interactive_groupby=t),g({filterState:{value:t.length?t:null},extraFormData:l})};(0,o.useEffect)((()=>{x(F.value)}),[JSON.stringify(F.value),k]),(0,o.useEffect)((()=>{x(null!=Z?Z:null)}),[JSON.stringify(Z),k]);const y=(0,n.Z)(c.groupby).map(s.Z),D=null!=(t=y[0])&&t.length?y[0]:null,$=D?l.filter((e=>D.includes(e.column_name))):l,_=l?$:[],A=0===_.length?(0,u.t)("No columns"):(0,u.tn)("%s option","%s options",_.length,_.length),E={};F.validateMessage&&(E.extra=(0,h.tZ)(r.Am,{status:F.validateStatus},F.validateMessage));const K=_.map((e=>{const{column_name:t,verbose_name:l}=e;return{label:null!=l?l:t,value:t}}));return(0,h.tZ)(r.un,{height:d,width:v},(0,h.tZ)(r.jp,(0,a.Z)({validateStatus:F.validateStatus},E),(0,h.tZ)(i.Ph,{allowClear:!0,value:C,placeholder:A,mode:k?"multiple":void 0,onChange:x,onBlur:b,onFocus:f,onMouseEnter:m,onMouseLeave:p,ref:S,options:K,onDropdownVisibleChange:w})))}},174448:(e,t,l)=>{l.d(t,{Am:()=>i,h2:()=>s,jp:()=>o,un:()=>u});var a=l(751995),n=l(804591);const s=0,u=a.iK.div`
  min-height: ${({height:e})=>e}px;
  width: ${({width:e})=>e===s?"100%":`${e}px`};
`,o=(0,a.iK)(n.Z)`
  &.ant-row.ant-form-item {
    margin: 0;
  }
`,i=a.iK.div`
  color: ${({theme:e,status:t="error"})=>{var l;return null==(l=e.colors[t])?void 0:l.base}};
`}}]);
//# sourceMappingURL=4ae14134fc18627fcca1.chunk.js.map