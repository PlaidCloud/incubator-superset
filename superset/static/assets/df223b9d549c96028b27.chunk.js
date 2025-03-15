"use strict";(globalThis.webpackChunksuperset=globalThis.webpackChunksuperset||[]).push([[1948],{281948:(t,e,a)=>{a.r(e),a.d(e,{default:()=>d});var n=a(573126),s=a(355786),l=a(61988),i=a(667294),r=a(104715),o=a(174448),u=a(211965);function d(t){const{data:e,formData:a,height:d,width:h,setDataMask:v,setHoveredFilter:c,unsetHoveredFilter:g,setFocusedFilter:f,unsetFocusedFilter:p,setFilterActive:m,filterState:w,inputRef:F}=t,{defaultValue:S}=a,[b,Z]=(0,i.useState)(null!=S?S:[]),M=(0,i.useMemo)((()=>e.reduce(((t,{duration:e,name:a})=>({...t,[e]:a})),{})),[JSON.stringify(e)]),k=t=>{const e=(0,s.Z)(t),[a]=e,n=a?M[a]:void 0,l={};a&&(l.time_grain_sqla=a),Z(e),v({extraFormData:l,filterState:{label:n,value:e.length?e:null}})};(0,i.useEffect)((()=>{k(null!=S?S:[])}),[JSON.stringify(S)]),(0,i.useEffect)((()=>{var t;k(null!=(t=w.value)?t:[])}),[JSON.stringify(w.value)]);const C=0===(e||[]).length?(0,l.t)("No data"):(0,l.tn)("%s option","%s options",e.length,e.length),x={};w.validateMessage&&(x.extra=(0,u.tZ)(o.Am,{status:w.validateStatus},w.validateMessage));const D=(e||[]).map((t=>{const{name:e,duration:a}=t;return{label:e,value:a}}));return(0,u.tZ)(o.un,{height:d,width:h},(0,u.tZ)(o.jp,(0,n.Z)({validateStatus:w.validateStatus},x),(0,u.tZ)(r.Ph,{allowClear:!0,value:b,placeholder:C,onChange:k,onBlur:p,onFocus:f,onMouseEnter:c,onMouseLeave:g,ref:F,options:D,onDropdownVisibleChange:m})))}},174448:(t,e,a)=>{a.d(e,{Am:()=>o,h2:()=>l,jp:()=>r,un:()=>i});var n=a(751995),s=a(804591);const l=0,i=n.iK.div`
  min-height: ${({height:t})=>t}px;
  width: ${({width:t})=>t===l?"100%":`${t}px`};
`,r=(0,n.iK)(s.Z)`
  &.ant-row.ant-form-item {
    margin: 0;
  }
`,o=n.iK.div`
  color: ${({theme:t,status:e="error"})=>{var a;return null==(a=t.colors[e])?void 0:a.base}};
`}}]);
//# sourceMappingURL=df223b9d549c96028b27.chunk.js.map