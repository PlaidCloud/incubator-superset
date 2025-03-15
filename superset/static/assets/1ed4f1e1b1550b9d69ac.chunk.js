"use strict";(globalThis.webpackChunksuperset=globalThis.webpackChunksuperset||[]).push([[8438],{727678:(t,e,n)=>{function a(t){var e=t.getBoundingClientRect(),n=document.documentElement;return{left:e.left+(window.pageXOffset||n.scrollLeft)-(n.clientLeft||document.body.clientLeft||0),top:e.top+(window.pageYOffset||n.scrollTop)-(n.clientTop||document.body.clientTop||0)}}n.d(e,{os:()=>a})},45598:(t,e,n)=>{var a=n(564836).default;Object.defineProperty(e,"__esModule",{value:!0}),e.default=function t(e){var n=arguments.length>1&&void 0!==arguments[1]?arguments[1]:{},a=[];return i.default.Children.forEach(e,(function(e){(null!=e||n.keepEmpty)&&(Array.isArray(e)?a=a.concat(t(e)):(0,l.isFragment)(e)&&e.props?a=a.concat(t(e.props.children,n)):a.push(e))})),a};var i=a(n(667294)),l=n(659864)},897596:(t,e,n)=>{var a=n(564836).default;Object.defineProperty(e,"__esModule",{value:!0}),e.default=function(t,e,n,a){var l=i.default.unstable_batchedUpdates?function(t){i.default.unstable_batchedUpdates(n,t)}:n;return t.addEventListener&&t.addEventListener(e,l,a),{remove:function(){t.removeEventListener&&t.removeEventListener(e,l,a)}}};var i=a(n(590731))},654887:(t,e)=>{Object.defineProperty(e,"__esModule",{value:!0}),e.get=function(t,e){var o=arguments.length,r=l(t);return e=i[e]?"cssFloat"in t.style?"cssFloat":"styleFloat":e,1===o?r:function(t,e,i){if(e=e.toLowerCase(),"auto"===i){if("height"===e)return t.offsetHeight;if("width"===e)return t.offsetWidth}return e in a||(a[e]=n.test(e)),a[e]?parseFloat(i)||0:i}(t,e,r[e]||t.style[e])},e.getClientSize=function(){return{width:document.documentElement.clientWidth,height:window.innerHeight||document.documentElement.clientHeight}},e.getDocSize=function(){return{width:Math.max(document.documentElement.scrollWidth,document.body.scrollWidth),height:Math.max(document.documentElement.scrollHeight,document.body.scrollHeight)}},e.getOffset=function(t){var e=t.getBoundingClientRect(),n=document.documentElement;return{left:e.left+(window.pageXOffset||n.scrollLeft)-(n.clientLeft||document.body.clientLeft||0),top:e.top+(window.pageYOffset||n.scrollTop)-(n.clientTop||document.body.clientTop||0)}},e.getOuterHeight=function(t){return t===document.body?window.innerHeight||document.documentElement.clientHeight:t.offsetHeight},e.getOuterWidth=function(t){return t===document.body?document.documentElement.clientWidth:t.offsetWidth},e.getScroll=function(){return{scrollLeft:Math.max(document.documentElement.scrollLeft,document.body.scrollLeft),scrollTop:Math.max(document.documentElement.scrollTop,document.body.scrollTop)}},e.set=function t(e,a,o){var r=arguments.length;if(a=i[a]?"cssFloat"in e.style?"cssFloat":"styleFloat":a,3===r)return"number"==typeof o&&n.test(a)&&(o="".concat(o,"px")),e.style[a]=o,o;for(var s in a)a.hasOwnProperty(s)&&t(e,s,a[s]);return l(e)};var n=/margin|padding|width|height|max|min|offset/,a={left:!0,top:!0},i={cssFloat:1,styleFloat:1,float:1};function l(t){return 1===t.nodeType?t.ownerDocument.defaultView.getComputedStyle(t,null):{}}},955331:(t,e)=>{Object.defineProperty(e,"__esModule",{value:!0}),e.default=void 0,e.default=function(t){if(!t)return!1;if(t instanceof HTMLElement&&t.offsetParent)return!0;if(t instanceof SVGGraphicsElement&&t.getBBox){var e=t.getBBox(),n=e.width,a=e.height;if(n||a)return!0}if(t instanceof HTMLElement&&t.getBoundingClientRect){var i=t.getBoundingClientRect(),l=i.width,o=i.height;if(l||o)return!0}return!1}},808259:(t,e)=>{var n;function a(t){if("undefined"==typeof document)return 0;if(t||void 0===n){var e=document.createElement("div");e.style.width="100%",e.style.height="200px";var a=document.createElement("div"),i=a.style;i.position="absolute",i.top="0",i.left="0",i.pointerEvents="none",i.visibility="hidden",i.width="200px",i.height="150px",i.overflow="hidden",a.appendChild(e),document.body.appendChild(a);var l=e.offsetWidth;a.style.overflow="scroll";var o=e.offsetWidth;l===o&&(o=a.clientWidth),document.body.removeChild(a),n=l-o}return n}function i(t){var e=t.match(/^(.*)px$/),n=Number(null==e?void 0:e[1]);return Number.isNaN(n)?a():n}Object.defineProperty(e,"__esModule",{value:!0}),e.default=a,e.getTargetScrollBarSize=function(t){if(!("undefined"!=typeof document&&t&&t instanceof Element))return{width:0,height:0};var e=getComputedStyle(t,"::-webkit-scrollbar"),n=e.width,a=e.height;return{width:i(n),height:i(a)}}},318545:(t,e,n)=>{var a=n(475263).default;Object.defineProperty(e,"__esModule",{value:!0}),e.default=function(t){var e=i.useRef();return e.current=t,i.useCallback((function(){for(var t,n=arguments.length,a=new Array(n),i=0;i<n;i++)a[i]=arguments[i];return null===(t=e.current)||void 0===t?void 0:t.call.apply(t,[e].concat(a))}),[])};var i=a(n(667294))},682546:(t,e,n)=>{var a=n(564836).default,i=n(475263).default;Object.defineProperty(e,"__esModule",{value:!0}),e.useLayoutUpdateEffect=e.default=void 0;var l=i(n(667294)),o=(0,a(n(819158)).default)()?l.useLayoutEffect:l.useEffect,r=o;e.default=r,e.useLayoutUpdateEffect=function(t,e){var n=l.useRef(!0);o((function(){if(!n.current)return t()}),e),o((function(){return n.current=!1,function(){n.current=!0}}),[])}},260869:(t,e,n)=>{var a=n(475263).default,i=n(564836).default;Object.defineProperty(e,"__esModule",{value:!0}),e.default=function(t,e){var n=e||{},a=n.defaultValue,i=n.value,h=n.onChange,p=n.postState,g=(0,c.default)((function(){var e,n=void 0;return u(i)?(n=i,e=l.PROP):u(a)?(n="function"==typeof a?a():a,e=l.PROP):(n="function"==typeof t?t():t,e=l.INNER),[n,e,n]})),m=(0,o.default)(g,2),f=m[0],v=m[1],b=u(i)?i:f[0],y=p?p(b):b;(0,d.useLayoutUpdateEffect)((function(){v((function(t){var e=(0,o.default)(t,1)[0];return[i,l.PROP,e]}))}),[i]);var x=r.useRef(),Z=(0,s.default)((function(t,e){v((function(e){var n=(0,o.default)(e,3),a=n[0],i=n[1],r=n[2],s="function"==typeof t?t(a):t;if(s===a)return e;var d=i===l.INNER&&x.current!==r?r:a;return[s,l.INNER,d]}),e)})),w=(0,s.default)(h);return(0,d.default)((function(){var t=(0,o.default)(f,3),e=t[0],n=t[1],a=t[2];e!==a&&n===l.INNER&&(w(e,a),x.current=a)}),[f]),[y,Z]};var l,o=i(n(627424)),r=a(n(667294)),s=i(n(318545)),d=a(n(682546)),c=i(n(688558));function u(t){return void 0!==t}!function(t){t[t.INNER=0]="INNER",t[t.PROP=1]="PROP"}(l||(l={}))},688558:(t,e,n)=>{var a=n(475263).default,i=n(564836).default;Object.defineProperty(e,"__esModule",{value:!0}),e.default=function(t){var e=o.useRef(!1),n=o.useState(t),a=(0,l.default)(n,2),i=a[0],r=a[1];return o.useEffect((function(){return e.current=!1,function(){e.current=!0}}),[]),[i,function(t,n){n&&e.current||r(t)}]};var l=i(n(627424)),o=a(n(667294))},751794:(t,e,n)=>{n.d(e,{Z:()=>i});var a=n(667294);const i=(t,e)=>{var n,i;const[l,o]=(0,a.useState)(0),[r,s]=(0,a.useState)(!1),d=(0,a.useRef)({scrollWidth:0,parentElementWidth:0,plusRefWidth:0});return(0,a.useLayoutEffect)((()=>{var n;const a=t.current,i=null==e?void 0:e.current;if(!a)return;const{scrollWidth:l,clientWidth:r,childNodes:c}=a,u=d.current,h=(null==(n=a.parentElement)?void 0:n.clientWidth)||0,p=(null==i?void 0:i.offsetWidth)||0;if(d.current={scrollWidth:l,parentElementWidth:h,plusRefWidth:p},u.parentElementWidth!==h||u.scrollWidth!==l||u.plusRefWidth!==p)if(l>r){const t=6,e=(null==i?void 0:i.offsetWidth)||0,n=r-t,a=c.length;let l=0,d=0;for(let i=0;i<a;i+=1)n-t-l-e<=0&&(d+=1),l+=c[i].offsetWidth;a>1&&d?(s(!0),o(d)):(s(!1),o(1))}else s(!1),o(0)}),[null==(n=t.current)?void 0:n.offsetWidth,null==(i=t.current)?void 0:i.clientWidth,t]),[l,r]}},852564:(t,e,n)=>{n.d(e,{u:()=>Z});var a=n(573126),i=n(667294),l=n(211965),o=n(751995),r=n(61988),s=n(104715),d=n(358593),c=n(899612);const u=t=>l.iv`
  display: flex;
  font-size: ${t.typography.sizes.xl}px;
  font-weight: ${t.typography.weights.bold};
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;

  & .dynamic-title,
  & .dynamic-title-input {
    display: inline-block;
    max-width: 100%;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  & .dynamic-title {
    cursor: default;
  }
  & .dynamic-title-input {
    border: none;
    padding: 0;
    outline: none;

    &::placeholder {
      color: ${t.colors.grayscale.light1};
    }
  }

  & .input-sizer {
    position: absolute;
    left: -9999px;
    display: inline-block;
  }
`,h=({title:t,placeholder:e,onSave:n,canEdit:a,label:o})=>{const[s,h]=(0,i.useState)(!1),[p,g]=(0,i.useState)(t||""),m=(0,i.useRef)(null),[f,v]=(0,i.useState)(!1),{width:b,ref:y}=(0,c.NB)(),{width:x,ref:Z}=(0,c.NB)({refreshMode:"debounce"});(0,i.useEffect)((()=>{g(t)}),[t]),(0,i.useEffect)((()=>{if(s&&null!=m&&m.current&&(m.current.focus(),m.current.setSelectionRange)){const{length:t}=m.current.value;m.current.setSelectionRange(t,t),m.current.scrollLeft=m.current.scrollWidth}}),[s]),(0,i.useLayoutEffect)((()=>{null!=y&&y.current&&(y.current.textContent=p||e)}),[p,e,y]),(0,i.useEffect)((()=>{m.current&&m.current.scrollWidth>m.current.clientWidth?v(!0):v(!1)}),[b,x]);const w=(0,i.useCallback)((()=>{a&&!s&&h(!0)}),[a,s]),$=(0,i.useCallback)((()=>{if(!a)return;const e=p.trim();g(e),t!==e&&n(e),h(!1)}),[a,p,n,t]),U=(0,i.useCallback)((t=>{a&&s&&g(t.target.value)}),[a,s]),_=(0,i.useCallback)((t=>{var e;a&&"Enter"===t.key&&(t.preventDefault(),null==(e=m.current)||e.blur())}),[a]);return(0,l.tZ)("div",{css:u,ref:Z},(0,l.tZ)(d.u,{id:"title-tooltip",title:f&&p&&!s?p:null},a?(0,l.tZ)("input",{className:"dynamic-title-input","aria-label":null!=o?o:(0,r.t)("Title"),ref:m,onChange:U,onBlur:$,onClick:w,onKeyPress:_,placeholder:e,value:p,css:l.iv`
              cursor: ${s?"text":"pointer"};

              ${b&&b>0&&l.iv`
                width: ${b+1}px;
              `}
            `}):(0,l.tZ)("span",{className:"dynamic-title","aria-label":null!=o?o:(0,r.t)("Title"),ref:m},p)),(0,l.tZ)("span",{ref:y,className:"input-sizer","aria-hidden":!0,tabIndex:-1}))};var p=n(679789),g=n(236674),m=n(313322),f=n(835932);const v=t=>l.iv`
  width: ${8*t.gridUnit}px;
  height: ${8*t.gridUnit}px;
  padding: 0;
  border: 1px solid ${t.colors.primary.dark2};

  &.ant-btn > span.anticon {
    line-height: 0;
    transition: inherit;
  }

  &:hover:not(:focus) > span.anticon {
    color: ${t.colors.primary.light1};
  }
`,b=t=>l.iv`
  display: flex;
  flex-direction: row;
  align-items: center;
  flex-wrap: nowrap;
  justify-content: space-between;
  background-color: ${t.colors.grayscale.light5};
  height: ${16*t.gridUnit}px;
  padding: 0 ${4*t.gridUnit}px;

  .editable-title {
    overflow: hidden;

    & > input[type='button'],
    & > span {
      overflow: hidden;
      text-overflow: ellipsis;
      max-width: 100%;
      white-space: nowrap;
    }
  }

  span[role='button'] {
    display: flex;
    height: 100%;
  }

  .title-panel {
    display: flex;
    align-items: center;
    min-width: 0;
    margin-right: ${12*t.gridUnit}px;
  }

  .right-button-panel {
    display: flex;
    align-items: center;
  }
`,y=t=>l.iv`
  display: flex;
  align-items: center;
  padding-left: ${2*t.gridUnit}px;

  & .fave-unfave-icon {
    padding: 0 ${t.gridUnit}px;

    &:first-of-type {
      padding-left: 0;
    }
  }
`,x=t=>l.iv`
  margin-left: ${2*t.gridUnit}px;
`,Z=({editableTitleProps:t,showTitlePanelItems:e,certificatiedBadgeProps:n,showFaveStar:i,faveStarProps:d,titlePanelAdditionalItems:c,rightPanelAdditionalItems:u,additionalActionsMenu:Z,menuDropdownProps:w,showMenuDropdown:$=!0,tooltipProps:U})=>{const _=(0,o.Fg)();return(0,l.tZ)("div",{css:b,className:"header-with-actions"},(0,l.tZ)("div",{className:"title-panel"},(0,l.tZ)(h,t),e&&(0,l.tZ)("div",{css:y},(null==n?void 0:n.certifiedBy)&&(0,l.tZ)(p.Z,n),i&&(0,l.tZ)(g.Z,d),c)),(0,l.tZ)("div",{className:"right-button-panel"},u,(0,l.tZ)("div",{css:x},$&&(0,l.tZ)(s.Gj,(0,a.Z)({trigger:["click"],overlay:Z},w),(0,l.tZ)(f.Z,{css:v,buttonStyle:"tertiary","aria-label":(0,r.t)("Menu actions trigger"),tooltip:null==U?void 0:U.text,placement:null==U?void 0:U.placement},(0,l.tZ)(m.Z.MoreHoriz,{iconColor:_.colors.primary.dark2,iconSize:"l"}))))))}},280663:(t,e,n)=>{n.d(e,{Z:()=>d});var a=n(667294),i=n(929119),l=n(751995),o=n(961337),r=n(211965);const s=l.iK.div`
  position: absolute;
  height: 100%;

  :hover .sidebar-resizer::after {
    background-color: ${({theme:t})=>t.colors.primary.base};
  }

  .sidebar-resizer {
    // @z-index-above-sticky-header (100) + 1 = 101
    z-index: 101;
  }

  .sidebar-resizer::after {
    display: block;
    content: '';
    width: 1px;
    height: 100%;
    margin: 0 auto;
  }
`,d=({id:t,initialWidth:e,minWidth:n,maxWidth:l,enable:d,children:c})=>{const[u,h]=function(t,e){const n=(0,a.useRef)(),[i,l]=(0,a.useState)(e);return(0,a.useEffect)((()=>{var e;n.current=null!=(e=n.current)?e:(0,o.rV)(o.dR.common__resizable_sidebar_widths,{}),n.current[t]&&l(n.current[t])}),[t]),[i,function(e){l(e),(0,o.LS)(o.dR.common__resizable_sidebar_widths,{...n.current,[t]:e})}]}(t,e);return(0,r.tZ)(a.Fragment,null,(0,r.tZ)(s,null,(0,r.tZ)(i.e,{enable:{right:d},handleClasses:{right:"sidebar-resizer"},size:{width:u,height:"100%"},minWidth:n,maxWidth:l,onResizeStop:(t,e,n,a)=>h(u+a.width)})),c(u))}},903720:(t,e,n)=>{n.r(e),n.d(e,{datasetReducer:()=>ce,default:()=>he});var a=n(667294),i=n(616550),l=n(431069),o=n(61988),r=n(68492),s=n(115926),d=n.n(s),c=n(672570);const u=(t,e)=>{const[n,i]=(0,a.useState)([]),s=e?encodeURIComponent(e):void 0,u=(0,a.useCallback)((async t=>{let e,n=[],a=0;for(;void 0===e||n.length<e;){const i=d().encode_uri({filters:t,page:a});try{const t=await l.Z.get({endpoint:`/api/v1/dataset/?q=${i}`});({count:e}=t.json);const{json:{result:o}}=t;n=[...n,...o],a+=1}catch(t){(0,c.Gb)((0,o.t)("There was an error fetching dataset")),r.Z.error((0,o.t)("There was an error fetching dataset"),t)}}i(n)}),[]);(0,a.useEffect)((()=>{const n=[{col:"database",opr:"rel_o_m",value:null==t?void 0:t.id},{col:"schema",opr:"eq",value:s},{col:"sql",opr:"dataset_is_null_or_empty",value:!0}];e&&u(n)}),[null==t?void 0:t.id,e,s,u]);const h=(0,a.useMemo)((()=>null==n?void 0:n.map((t=>t.table_name))),[n]);return{datasets:n,datasetNames:h}};var h,p=n(852564),g=n(835932),m=n(313322),f=n(683862);!function(t){t[t.selectDatabase=0]="selectDatabase",t[t.selectSchema=1]="selectSchema",t[t.selectTable=2]="selectTable",t[t.changeDataset=3]="changeDataset"}(h||(h={}));var v=n(751995),b=n(211965);const y=v.iK.div`
  flex-grow: 1;
  display: flex;
  flex-direction: column;
  background-color: ${({theme:t})=>t.colors.grayscale.light5};
`,x=v.iK.div`
  width: ${({theme:t,width:e})=>null!=e?e:80*t.gridUnit}px;
  max-width: ${({theme:t,width:e})=>null!=e?e:80*t.gridUnit}px;
  flex-direction: column;
  flex: 1 0 auto;
`,Z=v.iK.div`
  display: flex;
  flex-direction: column;
  flex-grow: 1;
`,w=v.iK.div`
  width: 100%;
  height: 100%;
  display: flex;
  flex-direction: row;
`,$=(0,v.iK)(w)`
  flex: 1 0 auto;
  position: relative;
`,U=(0,v.iK)(w)`
  flex: 1 0 auto;
  height: auto;
`,_=(0,v.iK)(w)`
  flex: 0 0 auto;
  height: ${({theme:t})=>16*t.gridUnit}px;
  z-index: 0;
`,E=v.iK.div`
  ${({theme:t})=>`\n  flex: 0 0 auto;\n  height: ${16*t.gridUnit}px;\n  border-bottom: 2px solid ${t.colors.grayscale.light2};\n\n  .header-with-actions {\n    height: ${15.5*t.gridUnit}px;\n  }\n  `}
`,S=v.iK.div`
  ${({theme:t})=>`\n  margin: ${4*t.gridUnit}px;\n  font-size: ${t.typography.sizes.xl}px;\n  font-weight: ${t.typography.weights.bold};\n  `}
`,T=v.iK.div`
  ${({theme:t})=>`\n  height: 100%;\n  border-right: 1px solid ${t.colors.grayscale.light2};\n  `}
`,C=v.iK.div`
  width: 100%;
  position: relative;
`,P=v.iK.div`
  ${({theme:t})=>`\n  border-left: 1px solid ${t.colors.grayscale.light2};\n  color: ${t.colors.success.base};\n  `}
`,k=v.iK.div`
  ${({theme:t})=>`\n  height: ${16*t.gridUnit}px;\n  width: 100%;\n  border-top: 1px solid ${t.colors.grayscale.light2};\n  border-bottom: 1px solid ${t.colors.grayscale.light2};\n  color: ${t.colors.info.base};\n  border-top: ${t.gridUnit/4}px solid\n    ${t.colors.grayscale.light2};\n  padding: ${4*t.gridUnit}px;\n  display: flex;\n  justify-content: flex-end;\n  background-color: ${t.colors.grayscale.light5};\n  z-index: ${t.zIndex.max}\n  `}
`,I=v.iK.div`
  .ant-btn {
    span {
      margin-right: 0;
    }

    &:disabled {
      svg {
        color: ${({theme:t})=>t.colors.grayscale.light1};
      }
    }
  }
`,R=t=>b.iv`
  width: ${21.5*t.gridUnit}px;

  &:disabled {
    background-color: ${t.colors.grayscale.light3};
    color: ${t.colors.grayscale.light1};
  }
`,M=(0,o.t)("New dataset"),N={text:(0,o.t)("Select a database table and create dataset"),placement:"bottomRight"},L=()=>(0,b.tZ)(g.Z,{buttonStyle:"primary",tooltip:null==N?void 0:N.text,placement:null==N?void 0:N.placement,disabled:!0,css:R},(0,b.tZ)(m.Z.Save,{iconSize:"m"}),(0,o.t)("Save")),z=()=>(0,b.tZ)(f.Menu,null,(0,b.tZ)(f.Menu.Item,null,(0,o.t)("Settings")),(0,b.tZ)(f.Menu.Item,null,(0,o.t)("Delete")));function O({setDataset:t,title:e=M,editing:n=!1}){const i={title:null!=e?e:M,placeholder:M,onSave:e=>{t({type:h.changeDataset,payload:{name:"dataset_name",value:e}})},canEdit:!1,label:(0,o.t)("dataset name")};return(0,b.tZ)(I,null,n?(0,b.tZ)(p.u,{editableTitleProps:i,showTitlePanelItems:!1,showFaveStar:!1,faveStarProps:{itemId:1,saveFaveStar:()=>{}},titlePanelAdditionalItems:(0,b.tZ)(a.Fragment,null),rightPanelAdditionalItems:L(),additionalActionsMenu:z(),menuDropdownProps:{disabled:!0},tooltipProps:N}):(0,b.tZ)(S,null,e||M))}var K,W,D=n(782607),V=n(171262),F=n(573126),j=n(473727),A=n(355786),H=n(493197),B=n(94301);function q(){return q=Object.assign?Object.assign.bind():function(t){for(var e=1;e<arguments.length;e++){var n=arguments[e];for(var a in n)({}).hasOwnProperty.call(n,a)&&(t[a]=n[a])}return t},q.apply(null,arguments)}const X=({title:t,titleId:e,...n},i)=>a.createElement("svg",q({xmlns:"http://www.w3.org/2000/svg",width:160,height:166,fill:"none",ref:i,"aria-labelledby":e},n),t?a.createElement("title",{id:e},t):null,K||(K=a.createElement("path",{fill:"#FAFAFA",fillRule:"evenodd",d:"M123.638 8a.5.5 0 0 0-.5.5V158h28.758V8.5a.5.5 0 0 0-.5-.5h-27.758ZM84.793 40.643a.5.5 0 0 1 .5-.5h27.759a.5.5 0 0 1 .5.5V158H84.793V40.643ZM46.95 72.285a.5.5 0 0 0-.5.5V158h28.758V72.785a.5.5 0 0 0-.5-.5H46.95ZM8.604 93.715a.5.5 0 0 0-.5.5V158h28.758V94.215a.5.5 0 0 0-.5-.5H8.604Z",clipRule:"evenodd"})),W||(W=a.createElement("path",{fill:"#D9D9D9",d:"M123.138 158h-.5v.5h.5v-.5Zm28.758 0v.5h.5v-.5h-.5Zm-38.344 0v.5h.5v-.5h-.5Zm-28.759 0h-.5v.5h.5v-.5Zm-38.344-.001h-.5v.5h.5v-.5Zm28.758 0v.5h.5v-.5h-.5ZM8.104 158h-.5v.5h.5v-.5Zm28.758 0v.5h.5v-.5h-.5ZM123.638 8.5v-1a1 1 0 0 0-1 1h1Zm0 149.5V8.5h-1V158h1Zm28.258-.5h-28.758v1h28.758v-1Zm-.5-149V158h1V8.5h-1Zm0 0h1a1 1 0 0 0-1-1v1Zm-27.758 0h27.758v-1h-27.758v1ZM85.293 39.643a1 1 0 0 0-1 1h1v-1Zm27.759 0H85.293v1h27.759v-1Zm1 1a1 1 0 0 0-1-1v1h1Zm0 117.357V40.643h-1V158h1Zm-29.259.5h28.759v-1H84.793v1Zm-.5-117.857V158h1V40.643h-1ZM46.95 72.785v-1a1 1 0 0 0-1 1h1Zm0 85.214V72.785h-1V158h1Zm28.258-.5H46.45v1h28.758v-1Zm-.5-84.714V158h1V72.785h-1Zm0 0h1a1 1 0 0 0-1-1v1Zm-27.758 0h27.758v-1H46.95v1ZM8.604 94.215v-1a1 1 0 0 0-1 1h1Zm0 63.785V94.215h-1V158h1Zm28.258-.5H8.104v1h28.758v-1Zm-.5-63.285V158h1V94.215h-1Zm0 0h1a1 1 0 0 0-1-1v1Zm-27.758 0h27.758v-1H8.604v1Z"}))),G=(0,a.forwardRef)(X);var Y=n(414114),Q=n(34858),J=n(593139),tt=n(730381),et=n.n(tt),nt=n(751794),at=n(358593);const it=v.iK.div`
  & > span {
    width: 100%;
    display: flex;

    .ant-tooltip-open {
      display: inline;
    }
  }
`,lt=v.iK.span`
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  display: inline-block;
  width: 100%;
  vertical-align: bottom;
`,ot=v.iK.span`
  &:not(:last-child)::after {
    content: ', ';
  }
`,rt=v.iK.div`
  .link {
    color: ${({theme:t})=>t.colors.grayscale.light5};
    display: block;
    text-decoration: underline;
  }
`,st=v.iK.span`
  ${({theme:t})=>`\n  cursor: pointer;\n  color: ${t.colors.primary.dark1};\n  font-weight: ${t.typography.weights.normal};\n  `}
`;function dt({items:t,renderVisibleItem:e=(t=>t),renderTooltipItem:n=(t=>t),getKey:i=(t=>t),maxLinks:l=20}){const r=(0,a.useRef)(null),s=(0,a.useRef)(null),[d,c]=(0,nt.Z)(r,s),u=(0,a.useMemo)((()=>t.length>l?t.length-l:void 0),[t,l]),h=(0,a.useMemo)((()=>(0,b.tZ)(lt,{ref:r},t.map((t=>(0,b.tZ)(ot,{key:i(t)},e(t)))))),[i,t,e]),p=(0,a.useMemo)((()=>t.slice(0,l).map((t=>(0,b.tZ)(rt,{key:i(t)},n(t))))),[i,t,l,n]);return(0,b.tZ)(it,null,(0,b.tZ)(at.u,{placement:"top",title:d?(0,b.tZ)(a.Fragment,null,p,u&&(0,b.tZ)("span",null,(0,o.t)("+ %s more",u))):null},h,c&&(0,b.tZ)(st,{ref:s},"+",d)))}const ct=t=>({key:t.id,to:`/superset/dashboard/${t.id}`,target:"_blank",rel:"noreferer noopener",children:t.dashboard_title}),ut=t=>b.iv`
  color: ${t.colors.grayscale.light5};
  text-decoration: underline;
  &:hover {
    color: inherit;
  }
`,ht=[{key:"slice_name",title:(0,o.t)("Chart"),width:"320px",sorter:!0,render:(t,e)=>(0,b.tZ)(j.rU,{to:e.url},e.slice_name)},{key:"owners",title:(0,o.t)("Chart owners"),width:"242px",render:(t,e)=>{var n,a;return(0,b.tZ)(dt,{items:null!=(n=null==(a=e.owners)?void 0:a.map((t=>`${t.first_name} ${t.last_name}`)))?n:[]})}},{key:"last_saved_at",title:(0,o.t)("Chart last modified"),width:"209px",sorter:!0,defaultSortOrder:"descend",render:(t,e)=>e.last_saved_at?et().utc(e.last_saved_at).fromNow():null},{key:"last_saved_by.first_name",title:(0,o.t)("Chart last modified by"),width:"216px",sorter:!0,render:(t,e)=>e.last_saved_by?`${e.last_saved_by.first_name} ${e.last_saved_by.last_name}`:null},{key:"dashboards",title:(0,o.t)("Dashboard usage"),width:"420px",render:(t,e)=>(0,b.tZ)(dt,{items:e.dashboards,renderVisibleItem:t=>(0,b.tZ)(j.rU,ct(t)),renderTooltipItem:t=>(0,b.tZ)(j.rU,(0,F.Z)({},ct(t),{css:ut})),getKey:t=>t.id})}],pt=t=>b.iv`
  && th.ant-table-cell {
    color: ${t.colors.grayscale.light1};
  }

  .ant-table-placeholder {
    display: none;
  }
`,gt=(0,b.tZ)(a.Fragment,null,(0,b.tZ)(m.Z.PlusOutlined,{iconSize:"m",css:b.iv`
        & > .anticon {
          line-height: 0;
        }
      `}),(0,o.t)("Create chart with dataset")),mt=(0,v.iK)(B.XJ)`
  margin: ${({theme:t})=>13*t.gridUnit}px 0;
`,ft=({datasetId:t})=>{const{loading:e,recordCount:n,data:i,onChange:l}=(t=>{const{addDangerToast:e}=(0,Y.e1)(),n=(0,a.useMemo)((()=>[{id:"datasource_id",operator:J.p.equals,value:t}]),[t]),{state:{loading:i,resourceCount:l,resourceCollection:r},fetchData:s}=(0,Q.Yi)("chart",(0,o.t)("chart"),e,!0,[],n),d=(0,a.useMemo)((()=>r.map((t=>({...t,key:t.id})))),[r]),c=(0,a.useCallback)(((t,e,n)=>{var a,i;const l=(null!=(a=t.current)?a:1)-1,o=null!=(i=t.pageSize)?i:0,r=(0,A.Z)(n).filter((({columnKey:t})=>"string"==typeof t)).map((({columnKey:t,order:e})=>({id:t,desc:"descend"===e})));s({pageIndex:l,pageSize:o,sortBy:r,filters:[]})}),[s]);return(0,a.useEffect)((()=>{s({pageIndex:0,pageSize:25,sortBy:[{id:"last_saved_at",desc:!0}],filters:[]})}),[s]),{loading:i,recordCount:l,data:d,onChange:c}})(t),r=(0,a.useCallback)((()=>window.open(`/explore/?dataset_type=table&dataset_id=${t}`,"_blank")),[t]);return(0,b.tZ)("div",{css:i.length?null:pt},(0,b.tZ)(H.ZP,{columns:ht,data:i,size:H.ex.MIDDLE,defaultPageSize:25,recordCount:n,loading:e,onChange:l}),i.length||e?null:(0,b.tZ)(mt,{image:(0,b.tZ)(G,null),title:(0,o.t)("No charts"),description:(0,o.t)("This dataset is not used to power any charts."),buttonText:gt,buttonAction:r}))},vt=(0,v.iK)(V.ZP)`
  ${({theme:t})=>`\n  margin-top: ${8.5*t.gridUnit}px;\n  padding-left: ${4*t.gridUnit}px;\n  padding-right: ${4*t.gridUnit}px;\n\n  .ant-tabs-top > .ant-tabs-nav::before {\n    width: ${50*t.gridUnit}px;\n  }\n  `}
`,bt=v.iK.div`
  ${({theme:t})=>`\n  .ant-badge {\n    width: ${8*t.gridUnit}px;\n    margin-left: ${2.5*t.gridUnit}px;\n  }\n  `}
`,yt={USAGE_TEXT:(0,o.t)("Usage"),COLUMNS_TEXT:(0,o.t)("Columns"),METRICS_TEXT:(0,o.t)("Metrics")},xt=({id:t})=>{const{usageCount:e}=(t=>{const[e,n]=(0,a.useState)(0),i=(0,a.useCallback)((()=>l.Z.get({endpoint:`/api/v1/dataset/${t}/related_objects`}).then((({json:t})=>{n(null==t?void 0:t.charts.count)})).catch((t=>{(0,c.Gb)((0,o.t)("There was an error fetching dataset's related objects")),r.Z.error(t)}))),[t]);return(0,a.useEffect)((()=>{t&&i()}),[t,i]),{usageCount:e}})(t),n=(0,b.tZ)(bt,null,(0,b.tZ)("span",null,yt.USAGE_TEXT),e>0&&(0,b.tZ)(D.Z,{count:e}));return(0,b.tZ)(vt,{moreIcon:null,fullWidth:!1},(0,b.tZ)(V.ZP.TabPane,{tab:yt.COLUMNS_TEXT,key:"1"}),(0,b.tZ)(V.ZP.TabPane,{tab:yt.METRICS_TEXT,key:"2"}),(0,b.tZ)(V.ZP.TabPane,{tab:n,key:"3"},(0,b.tZ)(ft,{datasetId:t})))};var Zt=n(229487);const wt=(t,e,n)=>{var a;return null==e||null==(a=e[t])||null==a.localeCompare?void 0:a.localeCompare(null==n?void 0:n[t])};var $t=n(289419);const Ut=v.iK.div`
  padding: ${({theme:t})=>8*t.gridUnit}px
    ${({theme:t})=>6*t.gridUnit}px;

  display: flex;
  align-items: center;
  justify-content: center;
  height: 100%;
`,_t=(0,v.iK)(B.XJ)`
  max-width: 50%;

  p {
    width: ${({theme:t})=>115*t.gridUnit}px;
  }
`,Et=(0,o.t)("Datasets can be created from database tables or SQL queries. Select a database table to the left or "),St=(0,o.t)("create dataset from SQL query"),Tt=(0,o.t)(" to open SQL Lab. From there you can save the query as a dataset."),Ct=(0,o.t)("Select dataset source"),Pt=(0,o.t)("No table columns"),kt=(0,o.t)("This database table does not contain any data. Please select a different table."),It=(0,o.t)("An Error Occurred"),Rt=(0,o.t)("Unable to load columns for the selected table. Please select a different table."),Mt=t=>{const{hasError:e,tableName:n,hasColumns:i}=t;let l="empty-dataset.svg",o=Ct,r=(0,b.tZ)(a.Fragment,null,Et,(0,b.tZ)(j.rU,{to:"/sqllab"},(0,b.tZ)("span",{role:"button",tabIndex:0},St)),Tt);return e?(o=It,r=(0,b.tZ)(a.Fragment,null,Rt),l=void 0):n&&!i&&(l="no-columns.svg",o=Pt,r=(0,b.tZ)(a.Fragment,null,kt)),(0,b.tZ)(Ut,null,(0,b.tZ)(_t,{image:l,title:o,description:r}))};var Nt;!function(t){t.ABSOLUTE="absolute",t.RELATIVE="relative"}(Nt||(Nt={}));const Lt=v.iK.div`
  ${({theme:t,position:e})=>`\n  position: ${e};\n  margin: ${4*t.gridUnit}px\n    ${3*t.gridUnit}px\n    ${3*t.gridUnit}px\n    ${6*t.gridUnit}px;\n  font-size: ${6*t.gridUnit}px;\n  font-weight: ${t.typography.weights.medium};\n  padding-bottom: ${3*t.gridUnit}px;\n\n  white-space: nowrap;\n  overflow: hidden;\n  text-overflow: ellipsis;\n\n  .anticon:first-of-type {\n    margin-right: ${4*t.gridUnit}px;\n  }\n\n  .anticon:nth-of-type(2) {\n    margin-left: ${4*t.gridUnit}px;\n  `}
`,zt=v.iK.div`
  ${({theme:t})=>`\n  margin-left: ${6*t.gridUnit}px;\n  margin-bottom: ${3*t.gridUnit}px;\n  font-weight: ${t.typography.weights.bold};\n  `}
`,Ot=v.iK.div`
  ${({theme:t})=>`\n  padding: ${8*t.gridUnit}px\n    ${6*t.gridUnit}px;\n  box-sizing: border-box;\n  display: flex;\n  align-items: center;\n  justify-content: center;\n  height: 100%;\n  position: absolute;\n  top: 0;\n  bottom: 0;\n  left: 0;\n  right: 0;\n  `}
`,Kt=v.iK.div`
  ${({theme:t})=>`\n  max-width: 50%;\n  width: 200px;\n\n  img {\n    width: 120px;\n    margin-left: 40px;\n  }\n\n  div {\n    width: 100%;\n    margin-top: ${3*t.gridUnit}px;\n    text-align: center;\n    font-weight: ${t.typography.weights.normal};\n    font-size: ${t.typography.sizes.l}px;\n    color: ${t.colors.grayscale.light1};\n  }\n  `}
`,Wt=v.iK.div`
  ${({theme:t})=>`\n  position: relative;\n  margin: ${3*t.gridUnit}px;\n  margin-left: ${6*t.gridUnit}px;\n  height: calc(100% - ${60*t.gridUnit}px);\n  overflow: auto;\n  `}
`,Dt=v.iK.div`
  ${({theme:t})=>`\n  position: relative;\n  margin: ${3*t.gridUnit}px;\n  margin-left: ${6*t.gridUnit}px;\n  height: calc(100% - ${30*t.gridUnit}px);\n  overflow: auto;\n  `}
`,Vt=v.iK.div`
  position: absolute;
  left: 0;
  top: 0;
  bottom: 0;
  right: 0;
`,Ft=(0,v.iK)(Zt.Z)`
  ${({theme:t})=>`\n  border: 1px solid ${t.colors.info.base};\n  padding: ${4*t.gridUnit}px;\n  margin: ${6*t.gridUnit}px ${6*t.gridUnit}px\n    ${8*t.gridUnit}px;\n  .view-dataset-button {\n    position: absolute;\n    top: ${4*t.gridUnit}px;\n    right: ${4*t.gridUnit}px;\n    font-weight: ${t.typography.weights.normal};\n\n    &:hover {\n      color: ${t.colors.secondary.dark3};\n      text-decoration: underline;\n    }\n  }\n  `}
`,jt=(0,o.t)("Refreshing columns"),At=(0,o.t)("Table columns"),Ht=(0,o.t)("Loading"),Bt=["5","10","15","25"],qt=[{title:"Column Name",dataIndex:"name",key:"name",sorter:(t,e)=>wt("name",t,e)},{title:"Datatype",dataIndex:"type",key:"type",width:"100px",sorter:(t,e)=>wt("type",t,e)}],Xt=(0,o.t)("This table already has a dataset associated with it. You can only associate one dataset with a table.\n"),Gt=(0,o.t)("View Dataset"),Yt=({tableName:t,columnList:e,loading:n,hasError:i,datasets:l})=>{var r;const s=(0,v.Fg)(),d=null!=(r=(null==e?void 0:e.length)>0)&&r,c=null==l?void 0:l.map((t=>t.table_name)),u=null==l?void 0:l.find((e=>e.table_name===t));let h,p;return n&&(p=(0,b.tZ)(Ot,null,(0,b.tZ)(Kt,null,(0,b.tZ)("img",{alt:Ht,src:$t}),(0,b.tZ)("div",null,jt)))),n||(h=!n&&t&&d&&!i?(0,b.tZ)(a.Fragment,null,(0,b.tZ)(zt,null,At),u?(0,b.tZ)(Wt,null,(0,b.tZ)(Vt,null,(0,b.tZ)(H.ZP,{loading:n,size:H.ex.SMALL,columns:qt,data:e,pageSizeOptions:Bt,defaultPageSize:25}))):(0,b.tZ)(Dt,null,(0,b.tZ)(Vt,null,(0,b.tZ)(H.ZP,{loading:n,size:H.ex.SMALL,columns:qt,data:e,pageSizeOptions:Bt,defaultPageSize:25})))):(0,b.tZ)(Mt,{hasColumns:d,hasError:i,tableName:t})),(0,b.tZ)(a.Fragment,null,t&&(0,b.tZ)(a.Fragment,null,(null==c?void 0:c.includes(t))&&(g=u,(0,b.tZ)(Ft,{closable:!1,type:"info",showIcon:!0,message:(0,o.t)("This table already has a dataset"),description:(0,b.tZ)(a.Fragment,null,Xt,(0,b.tZ)("span",{role:"button",onClick:()=>{window.open(null==g?void 0:g.explore_url,"_blank","noreferrer noopener popup=false")},tabIndex:0,className:"view-dataset-button"},Gt))})),(0,b.tZ)(Lt,{position:!n&&d?Nt.RELATIVE:Nt.ABSOLUTE,title:t||""},t&&(0,b.tZ)(m.Z.Table,{iconColor:s.colors.grayscale.base}),t)),h,p);var g},Qt=({tableName:t,dbId:e,schema:n,setHasColumns:i,datasets:s})=>{const[d,u]=(0,a.useState)([]),[h,p]=(0,a.useState)(!1),[g,m]=(0,a.useState)(!1),f=(0,a.useRef)(t);return(0,a.useEffect)((()=>{f.current=t,t&&n&&e&&(async t=>{const{dbId:e,tableName:n,schema:a}=t;p(!0),null==i||i(!1);const s=`/api/v1/database/${e}/table/${n}/${a}/`;try{const t=await l.Z.get({endpoint:s});if((t=>{let e=!0;if("string"!=typeof(null==t?void 0:t.name)&&(e=!1),e&&!Array.isArray(t.columns)&&(e=!1),e&&t.columns.length>0){const n=t.columns.some(((t,e)=>{const n=(t=>{let e=!0;const n="The object provided to isITableColumn does match the interface.";return"string"!=typeof(null==t?void 0:t.name)&&(e=!1,console.error(`${n} The property 'name' is required and must be a string`)),e&&"string"!=typeof(null==t?void 0:t.type)&&(e=!1,console.error(`${n} The property 'type' is required and must be a string`)),e})(t);return n||console.error(`The provided object does not match the IDatabaseTable interface. columns[${e}] is invalid and does not match the ITableColumn interface`),!n}));e=!n}return e})(null==t?void 0:t.json)){const e=t.json;e.name===f.current&&(u(e.columns),null==i||i(e.columns.length>0),m(!1))}else u([]),null==i||i(!1),m(!0),(0,c.Gb)((0,o.t)("The API response from %s does not match the IDatabaseTable interface.",s)),r.Z.error((0,o.t)("The API response from %s does not match the IDatabaseTable interface.",s))}catch(t){u([]),null==i||i(!1),m(!0)}finally{p(!1)}})({tableName:t,dbId:e,schema:n})}),[t,e,n]),(0,b.tZ)(Yt,{columnList:d,hasError:g,loading:h,tableName:t,datasets:s})};var Jt=n(517982),te=n(961337);const ee=v.iK.div`
  ${({theme:t})=>`\n    padding: ${4*t.gridUnit}px;\n    height: 100%;\n    background-color: ${t.colors.grayscale.light5};\n    position: relative;\n    .emptystate {\n      height: auto;\n      margin-top: ${17.5*t.gridUnit}px;\n    }\n    .section-title {\n      margin-top: ${5.5*t.gridUnit}px;\n      margin-bottom: ${11*t.gridUnit}px;\n      font-weight: ${t.typography.weights.bold};\n    }\n    .table-title {\n      margin-top: ${11*t.gridUnit}px;\n      margin-bottom: ${6*t.gridUnit}px;\n      font-weight: ${t.typography.weights.bold};\n    }\n    .options-list {\n      overflow: auto;\n      position: absolute;\n      bottom: 0;\n      top: ${92.25*t.gridUnit}px;\n      left: ${3.25*t.gridUnit}px;\n      right: 0;\n\n      .no-scrollbar {\n        margin-right: ${4*t.gridUnit}px;\n      }\n\n      .options {\n        cursor: pointer;\n        padding: ${1.75*t.gridUnit}px;\n        border-radius: ${t.borderRadius}px;\n        :hover {\n          background-color: ${t.colors.grayscale.light4}\n        }\n      }\n\n      .options-highlighted {\n        cursor: pointer;\n        padding: ${1.75*t.gridUnit}px;\n        border-radius: ${t.borderRadius}px;\n        background-color: ${t.colors.primary.dark1};\n        color: ${t.colors.grayscale.light5};\n      }\n\n      .options, .options-highlighted {\n        display: flex;\n        align-items: center;\n        justify-content: space-between;\n      }\n    }\n    form > span[aria-label="refresh"] {\n      position: absolute;\n      top: ${69*t.gridUnit}px;\n      left: ${42.75*t.gridUnit}px;\n      font-size: ${4.25*t.gridUnit}px;\n    }\n    .table-form {\n      margin-bottom: ${8*t.gridUnit}px;\n    }\n    .loading-container {\n      position: absolute;\n      top: ${89.75*t.gridUnit}px;\n      left: 0;\n      right: 0;\n      text-align: center;\n      img {\n        width: ${20*t.gridUnit}px;\n        margin-bottom: ${2.5*t.gridUnit}px;\n      }\n      p {\n        color: ${t.colors.grayscale.light1};\n      }\n    }\n`}
`;function ne({setDataset:t,dataset:e,datasetNames:n}){const{addDangerToast:i}=(0,Y.e1)(),l=(0,a.useCallback)((e=>{t({type:h.selectDatabase,payload:{db:e}})}),[t]);(0,a.useEffect)((()=>{const t=(0,te.rV)(te.dR.db,null);t&&l(t)}),[l]);const r=(0,a.useCallback)((t=>(0,b.tZ)(Jt.ez,{table:null!=n&&n.includes(t.value)?{...t,extra:{warning_markdown:(0,o.t)("This table already has a dataset")}}:t})),[n]);return(0,b.tZ)(ee,null,(0,b.tZ)(Jt.ZP,(0,F.Z)({database:null==e?void 0:e.db,handleError:i,emptyState:(0,B.UX)(!1),onDbChange:l,onSchemaChange:e=>{e&&t({type:h.selectSchema,payload:{name:"schema",value:e}})},onTableSelectChange:e=>{t({type:h.selectTable,payload:{name:"table_name",value:e}})},sqlLabMode:!1,customTableOptionLabelRenderer:r},(null==e?void 0:e.schema)&&{schema:e.schema})))}var ae=n(797381),ie=n(203741);const le=["db","schema","table_name"],oe=[ie.Ph,ie.FY,ie.Eh,ie.TA],re=(0,Y.ZP)((function({datasetObject:t,addDangerToast:e,hasColumns:n=!1,datasets:l}){const r=(0,i.k6)(),{createResource:s}=(0,Q.LE)("dataset",(0,o.t)("dataset"),e),d=(0,o.t)("Select a database table."),c=(0,o.t)("Create dataset and create chart"),u=!(null!=t&&t.table_name)||!n||(null==l?void 0:l.includes(null==t?void 0:t.table_name));return(0,b.tZ)(a.Fragment,null,(0,b.tZ)(g.Z,{onClick:()=>{if(t){const e=(t=>{let e=0;const n=Object.keys(t).reduce(((n,a)=>(le.includes(a)&&t[a]&&(e+=1),e)),0);return oe[n]})(t);(0,ae.logEvent)(e,t)}else(0,ae.logEvent)(ie.Ph,{});r.goBack()}},(0,o.t)("Cancel")),(0,b.tZ)(g.Z,{buttonStyle:"primary",disabled:u,tooltip:null!=t&&t.table_name?void 0:d,onClick:()=>{if(t){var e;const n={database:null==(e=t.db)?void 0:e.id,schema:t.schema,table_name:t.table_name};s(n).then((e=>{e&&"number"==typeof e&&((0,ae.logEvent)(ie.P$,t),r.push(`/chart/add/?dataset=${t.table_name}`))}))}}},c))}));var se=n(280663);function de({header:t,leftPanel:e,datasetPanel:n,rightPanel:a,footer:i}){const l=(0,v.Fg)();return(0,b.tZ)(y,null,t&&(0,b.tZ)(E,null,t),(0,b.tZ)($,null,e&&(0,b.tZ)(se.Z,{id:"dataset",initialWidth:80*l.gridUnit,minWidth:80*l.gridUnit,enable:!0},(t=>(0,b.tZ)(x,{width:t},(0,b.tZ)(T,null,e)))),(0,b.tZ)(Z,null,(0,b.tZ)(U,null,n&&(0,b.tZ)(C,null,n),a&&(0,b.tZ)(P,null,a)),(0,b.tZ)(_,null,i&&(0,b.tZ)(k,null,i)))))}function ce(t,e){const n={...t||{}};switch(e.type){case h.selectDatabase:return{...n,...e.payload,schema:null,table_name:null};case h.selectSchema:return{...n,[e.payload.name]:e.payload.value,table_name:null};case h.selectTable:return{...n,[e.payload.name]:e.payload.value};case h.changeDataset:return{...n,[e.payload.name]:e.payload.value};default:return null}}const ue="/tablemodelview/list/?pageIndex=0&sortColumn=changed_on_delta_humanized&sortOrder=desc";function he(){const[t,e]=(0,a.useReducer)(ce,null),[n,l]=(0,a.useState)(!1),[o,r]=(0,a.useState)(!1),{datasets:s,datasetNames:d}=u(null==t?void 0:t.db,null==t?void 0:t.schema),{datasetId:c}=(0,i.UO)();return(0,a.useEffect)((()=>{Number.isNaN(parseInt(c,10))||r(!0)}),[c]),(0,b.tZ)(de,{header:(0,b.tZ)(O,{setDataset:e,title:null==t?void 0:t.table_name}),leftPanel:o?null:(0,b.tZ)(ne,{setDataset:e,dataset:t,datasetNames:d}),datasetPanel:o?(0,b.tZ)(xt,{id:c}):(0,b.tZ)(Qt,{tableName:null==t?void 0:t.table_name,dbId:null==t||null==(h=t.db)?void 0:h.id,schema:null==t?void 0:t.schema,setHasColumns:l,datasets:s}),footer:(0,b.tZ)(re,{url:ue,datasetObject:t,hasColumns:n,datasets:d})});var h}}}]);
//# sourceMappingURL=1ed4f1e1b1550b9d69ac.chunk.js.map