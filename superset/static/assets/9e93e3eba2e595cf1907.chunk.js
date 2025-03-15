"use strict";(globalThis.webpackChunksuperset=globalThis.webpackChunksuperset||[]).push([[1880],{232871:(t,e,i)=>{var n;i.d(e,{p:()=>n}),function(t){t.DASHBOARDS="dashboards",t.DESCRIPTION="description",t.LAST_MODIFIED="lastModified",t.OWNER="owner",t.ROWS="rows",t.SQL="sql",t.TABLE="table",t.TAGS="tags"}(n||(n={}))},767697:(t,e,i)=>{i.d(e,{pG:()=>b.p,ZP:()=>Z});var n=i(187185),l=i.n(n),r=i(667294),o=i(899612),a=i(751995),s=i(358593),d=i(355786),c=i(61988),p=i(313322),u=i(211965);const h=a.iK.div`
  font-weight: ${({theme:t})=>t.typography.weights.bold};
`,f=({text:t,header:e})=>{const i=(0,d.Z)(t);return(0,u.tZ)(r.Fragment,null,e&&(0,u.tZ)(h,null,e),i.map((t=>(0,u.tZ)("div",{key:t},t))))},g=16,m={dashboards:0,table:1,sql:2,rows:3,tags:4,description:5,owner:6,lastModified:7},v=a.iK.div`
  ${({theme:t,count:e})=>`\n    display: flex;\n    align-items: center;\n    padding: 8px 12px;\n    background-color: ${t.colors.grayscale.light4};\n    color: ${t.colors.grayscale.base};\n    font-size: ${t.typography.sizes.s}px;\n    min-width: ${24+32*e-g}px;\n    border-radius: ${t.borderRadius}px;\n    line-height: 1;\n  `}
`,w=a.iK.div`
  ${({theme:t,collapsed:e,last:i,onClick:n})=>`\n    display: flex;\n    align-items: center;\n    max-width: ${174+(i?0:g)}px;\n    min-width: ${e?16+(i?0:g):94+(i?0:g)}px;\n    padding-right: ${i?0:g}px;\n    cursor: ${n?"pointer":"default"};\n    & .metadata-icon {\n      color: ${n&&e?t.colors.primary.base:t.colors.grayscale.base};\n      padding-right: ${e?0:8}px;\n      & .anticon {\n        line-height: 0;\n      }\n    }\n    & .metadata-text {\n      min-width: 70px;\n      overflow: hidden;\n      text-overflow: ${e?"unset":"ellipsis"};\n      white-space: nowrap;\n      text-decoration: ${n?"underline":"none"};\n      line-height: 1.4;\n    }\n  `}
`,y=a.iK.div`
  display: -webkit-box;
  -webkit-line-clamp: 20;
  -webkit-box-orient: vertical;
  overflow: hidden;
  text-overflow: ellipsis;
`,x=({barWidth:t,contentType:e,collapsed:i,last:n=!1,tooltipPlacement:l})=>{const{icon:o,title:a,tooltip:d=a}=(t=>{const{type:e}=t;switch(e){case b.p.DASHBOARDS:return{icon:p.Z.FundProjectionScreenOutlined,title:t.title,tooltip:t.description?(0,u.tZ)("div",null,(0,u.tZ)(f,{header:t.title,text:t.description})):void 0};case b.p.DESCRIPTION:return{icon:p.Z.BookOutlined,title:t.value};case b.p.LAST_MODIFIED:return{icon:p.Z.EditOutlined,title:t.value,tooltip:(0,u.tZ)("div",null,(0,u.tZ)(f,{header:(0,c.t)("Last modified"),text:t.value}),(0,u.tZ)(f,{header:(0,c.t)("Modified by"),text:t.modifiedBy}))};case b.p.OWNER:return{icon:p.Z.UserOutlined,title:t.createdBy,tooltip:(0,u.tZ)("div",null,(0,u.tZ)(f,{header:(0,c.t)("Created by"),text:t.createdBy}),!!t.owners&&(0,u.tZ)(f,{header:(0,c.t)("Owners"),text:t.owners}),(0,u.tZ)(f,{header:(0,c.t)("Created on"),text:t.createdOn}))};case b.p.ROWS:return{icon:p.Z.InsertRowBelowOutlined,title:t.title,tooltip:t.title};case b.p.SQL:return{icon:p.Z.ConsoleSqlOutlined,title:t.title,tooltip:t.title};case b.p.TABLE:return{icon:p.Z.Table,title:t.title,tooltip:t.title};case b.p.TAGS:return{icon:p.Z.TagsOutlined,title:t.values.join(", "),tooltip:(0,u.tZ)("div",null,(0,u.tZ)(f,{header:(0,c.t)("Tags"),text:t.values}))};default:throw Error(`Invalid type provided: ${e}`)}})(e),[h,g]=(0,r.useState)(!1),m=(0,r.useRef)(null),v=o,{type:x,onClick:Z}=e;(0,r.useEffect)((()=>{g(!!m.current&&m.current.scrollWidth>m.current.clientWidth)}),[t,g,e]);const $=(0,u.tZ)(w,{collapsed:i,last:n,onClick:Z?()=>Z(x):void 0},(0,u.tZ)(v,{iconSize:"l",className:"metadata-icon"}),!i&&(0,u.tZ)("span",{ref:m,className:"metadata-text"},a));return h||i||d&&d!==a?(0,u.tZ)(s.u,{placement:l,title:(0,u.tZ)(y,null,d)},$):$};var b=i(232871);const Z=({items:t,tooltipPlacement:e="top"})=>{const[i,n]=(0,r.useState)(),[a,s]=(0,r.useState)(!1),d=l()(t,((t,e)=>t.type===e.type)).sort(((t,e)=>m[t.type]-m[e.type])),c=d.length;if(c<2)throw Error("The minimum number of items for the metadata bar is 2.");if(c>6)throw Error("The maximum number of items for the metadata bar is 6.");const p=(0,r.useCallback)((t=>{const e=110*c-g;n(t),s(Boolean(t&&t<e))}),[c]),{ref:h}=(0,o.NB)({onResize:p});return(0,u.tZ)(v,{ref:h,count:c},d.map(((t,n)=>(0,u.tZ)(x,{barWidth:i,key:n,contentType:t,collapsed:a,last:n===c-1,tooltipPlacement:e}))))}},852564:(t,e,i)=>{i.d(e,{u:()=>b});var n=i(573126),l=i(667294),r=i(211965),o=i(751995),a=i(61988),s=i(104715),d=i(358593),c=i(899612);const p=t=>r.iv`
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
`,u=({title:t,placeholder:e,onSave:i,canEdit:n,label:o})=>{const[s,u]=(0,l.useState)(!1),[h,f]=(0,l.useState)(t||""),g=(0,l.useRef)(null),[m,v]=(0,l.useState)(!1),{width:w,ref:y}=(0,c.NB)(),{width:x,ref:b}=(0,c.NB)({refreshMode:"debounce"});(0,l.useEffect)((()=>{f(t)}),[t]),(0,l.useEffect)((()=>{if(s&&null!=g&&g.current&&(g.current.focus(),g.current.setSelectionRange)){const{length:t}=g.current.value;g.current.setSelectionRange(t,t),g.current.scrollLeft=g.current.scrollWidth}}),[s]),(0,l.useLayoutEffect)((()=>{null!=y&&y.current&&(y.current.textContent=h||e)}),[h,e,y]),(0,l.useEffect)((()=>{g.current&&g.current.scrollWidth>g.current.clientWidth?v(!0):v(!1)}),[w,x]);const Z=(0,l.useCallback)((()=>{n&&!s&&u(!0)}),[n,s]),$=(0,l.useCallback)((()=>{if(!n)return;const e=h.trim();f(e),t!==e&&i(e),u(!1)}),[n,h,i,t]),S=(0,l.useCallback)((t=>{n&&s&&f(t.target.value)}),[n,s]),k=(0,l.useCallback)((t=>{var e;n&&"Enter"===t.key&&(t.preventDefault(),null==(e=g.current)||e.blur())}),[n]);return(0,r.tZ)("div",{css:p,ref:b},(0,r.tZ)(d.u,{id:"title-tooltip",title:m&&h&&!s?h:null},n?(0,r.tZ)("input",{className:"dynamic-title-input","aria-label":null!=o?o:(0,a.t)("Title"),ref:g,onChange:S,onBlur:$,onClick:Z,onKeyPress:k,placeholder:e,value:h,css:r.iv`
              cursor: ${s?"text":"pointer"};

              ${w&&w>0&&r.iv`
                width: ${w+1}px;
              `}
            `}):(0,r.tZ)("span",{className:"dynamic-title","aria-label":null!=o?o:(0,a.t)("Title"),ref:g},h)),(0,r.tZ)("span",{ref:y,className:"input-sizer","aria-hidden":!0,tabIndex:-1}))};var h=i(679789),f=i(236674),g=i(313322),m=i(835932);const v=t=>r.iv`
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
`,w=t=>r.iv`
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
`,y=t=>r.iv`
  display: flex;
  align-items: center;
  padding-left: ${2*t.gridUnit}px;

  & .fave-unfave-icon {
    padding: 0 ${t.gridUnit}px;

    &:first-of-type {
      padding-left: 0;
    }
  }
`,x=t=>r.iv`
  margin-left: ${2*t.gridUnit}px;
`,b=({editableTitleProps:t,showTitlePanelItems:e,certificatiedBadgeProps:i,showFaveStar:l,faveStarProps:d,titlePanelAdditionalItems:c,rightPanelAdditionalItems:p,additionalActionsMenu:b,menuDropdownProps:Z,showMenuDropdown:$=!0,tooltipProps:S})=>{const k=(0,o.Fg)();return(0,r.tZ)("div",{css:w,className:"header-with-actions"},(0,r.tZ)("div",{className:"title-panel"},(0,r.tZ)(u,t),e&&(0,r.tZ)("div",{css:y},(null==i?void 0:i.certifiedBy)&&(0,r.tZ)(h.Z,i),l&&(0,r.tZ)(f.Z,d),c)),(0,r.tZ)("div",{className:"right-button-panel"},p,(0,r.tZ)("div",{css:x},$&&(0,r.tZ)(s.Gj,(0,n.Z)({trigger:["click"],overlay:b},Z),(0,r.tZ)(m.Z,{css:v,buttonStyle:"tertiary","aria-label":(0,a.t)("Menu actions trigger"),tooltip:null==S?void 0:S.text,placement:null==S?void 0:S.placement},(0,r.tZ)(g.Z.MoreHoriz,{iconColor:k.colors.primary.dark2,iconSize:"l"}))))))}}}]);
//# sourceMappingURL=9e93e3eba2e595cf1907.chunk.js.map