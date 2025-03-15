"use strict";(globalThis.webpackChunksuperset=globalThis.webpackChunksuperset||[]).push([[6284],{933726:(e,t,a)=>{a.d(t,{Y:()=>s});var r=a(61988);const s={name:(0,r.t)("SQL"),tabs:[{name:"Saved queries",label:(0,r.t)("Saved queries"),url:"/savedqueryview/list/",usesRouter:!0},{name:"Query history",label:(0,r.t)("Query history"),url:"/sqllab/history/",usesRouter:!0}]}},106189:(e,t,a)=>{a.d(t,{Z:()=>b});var r=a(573126),s=(a(667294),a(751995)),o=a(61988),i=a(833743),l=a(849889),n=a(453459),c=a(622489),u=a(600120),d=a(242110),g=a(313322),h=a(710222),p=a(211965);d.Z.registerLanguage("sql",i.Z),d.Z.registerLanguage("markdown",n.Z),d.Z.registerLanguage("html",l.Z),d.Z.registerLanguage("json",c.Z);const m=s.iK.div`
  margin-top: -24px;

  &:hover {
    svg {
      visibility: visible;
    }
  }

  svg {
    position: relative;
    top: 40px;
    left: 512px;
    visibility: hidden;
    margin: -4px;
    color: ${({theme:e})=>e.colors.grayscale.base};
  }
`;function b({addDangerToast:e,addSuccessToast:t,children:a,...s}){return(0,p.tZ)(m,null,(0,p.tZ)(g.Z.Copy,{tabIndex:0,role:"button",onClick:r=>{var s;r.preventDefault(),r.currentTarget.blur(),s=a,(0,h.Z)((()=>Promise.resolve(s))).then((()=>{t&&t((0,o.t)("SQL Copied!"))})).catch((()=>{e&&e((0,o.t)("Sorry, your browser does not support copying."))}))}}),(0,p.tZ)(d.Z,(0,r.Z)({style:u.Z},s),a))}},286185:(e,t,a)=>{a.d(t,{Z:()=>s});var r=a(667294);function s({queries:e,fetchData:t,currentQueryId:a}){const s=e.findIndex((e=>e.id===a)),[o,i]=(0,r.useState)(s),[l,n]=(0,r.useState)(!1),[c,u]=(0,r.useState)(!1);function d(){n(0===o),u(o===e.length-1)}function g(a){const r=o+(a?-1:1);r>=0&&r<e.length&&(t(e[r].id),i(r),d())}return(0,r.useEffect)((()=>{d()})),{handleKeyPress:function(t){o>=0&&o<e.length&&("ArrowDown"===t.key||"k"===t.key?(t.preventDefault(),g(!1)):"ArrowUp"!==t.key&&"j"!==t.key||(t.preventDefault(),g(!0)))},handleDataChange:g,disablePrevious:l,disableNext:c}}},436444:(e,t,a)=>{a.r(t),a.d(t,{default:()=>B});var r=a(667294),s=a(616550),o=a(473727),i=a(751995),l=a(61988),n=a(431069),c=a(343716),u=a(730381),d=a.n(u),g=a(440768),h=a(414114),p=a(34858),m=a(737921),b=a(586074),y=a(799299),Z=a(933726),v=a(593139),f=a(358593),x=a(242110),q=a(833743),S=a(600120),w=a(427600),k=a(400012),C=a(313322),$=a(774069),T=a(294184),D=a.n(T),L=a(835932),z=a(106189),H=a(286185),_=a(211965);const I=i.iK.div`
  color: ${({theme:e})=>e.colors.secondary.light2};
  font-size: ${({theme:e})=>e.typography.sizes.s}px;
  margin-bottom: 0;
  text-transform: uppercase;
`,U=i.iK.div`
  color: ${({theme:e})=>e.colors.grayscale.dark2};
  font-size: ${({theme:e})=>e.typography.sizes.m}px;
  padding: 4px 0 24px 0;
`,K=i.iK.div`
  margin: 0 0 ${({theme:e})=>6*e.gridUnit}px 0;
`,A=i.iK.div`
  display: inline;
  font-size: ${({theme:e})=>e.typography.sizes.s}px;
  padding: ${({theme:e})=>2*e.gridUnit}px
    ${({theme:e})=>4*e.gridUnit}px;
  margin-right: ${({theme:e})=>4*e.gridUnit}px;
  color: ${({theme:e})=>e.colors.secondary.dark1};

  &.active,
  &:focus,
  &:hover {
    background: ${({theme:e})=>e.colors.secondary.light4};
    border-bottom: none;
    border-radius: ${({theme:e})=>e.borderRadius}px;
    margin-bottom: ${({theme:e})=>2*e.gridUnit}px;
  }

  &:hover:not(.active) {
    background: ${({theme:e})=>e.colors.secondary.light5};
  }
`,P=(0,i.iK)($.default)`
  .ant-modal-body {
    padding: ${({theme:e})=>6*e.gridUnit}px;
  }

  pre {
    font-size: ${({theme:e})=>e.typography.sizes.xs}px;
    font-weight: ${({theme:e})=>e.typography.weights.normal};
    line-height: ${({theme:e})=>e.typography.sizes.l}px;
    height: 375px;
    border: none;
  }
`,Q=(0,h.ZP)((function({onHide:e,openInSqlLab:t,queries:a,query:s,fetchData:o,show:i,addDangerToast:n,addSuccessToast:c}){const{handleKeyPress:u,handleDataChange:d,disablePrevious:g,disableNext:h}=(0,H.Z)({queries:a,currentQueryId:s.id,fetchData:o}),[p,m]=(0,r.useState)("user"),{id:b,sql:y,executed_sql:Z}=s;return(0,_.tZ)("div",{role:"none",onKeyUp:u},(0,_.tZ)(P,{onHide:e,show:i,title:(0,l.t)("Query preview"),footer:(0,_.tZ)(r.Fragment,null,(0,_.tZ)(L.Z,{key:"previous-query",disabled:g,onClick:()=>d(!0)},(0,l.t)("Previous")),(0,_.tZ)(L.Z,{key:"next-query",disabled:h,onClick:()=>d(!1)},(0,l.t)("Next")),(0,_.tZ)(L.Z,{key:"open-in-sql-lab",buttonStyle:"primary",onClick:()=>t(b)},(0,l.t)("Open in SQL Lab")))},(0,_.tZ)(I,null,(0,l.t)("Tab name")),(0,_.tZ)(U,null,s.tab_name),(0,_.tZ)(K,null,(0,_.tZ)(A,{role:"button",className:D()({active:"user"===p}),onClick:()=>m("user")},(0,l.t)("User query")),(0,_.tZ)(A,{role:"button",className:D()({active:"executed"===p}),onClick:()=>m("executed")},(0,l.t)("Executed query"))),(0,_.tZ)(z.Z,{addDangerToast:n,addSuccessToast:c,language:"sql"},("user"===p?y:Z)||"")))}));var E=a(672570),J=a(83379);const N=(0,i.iK)(v.Z)`
  table .table-cell {
    vertical-align: top;
  }
`;x.Z.registerLanguage("sql",q.Z);const F=(0,i.iK)(x.Z)`
  height: ${({theme:e})=>26*e.gridUnit}px;
  overflow: hidden !important; /* needed to override inline styles */
  text-overflow: ellipsis;
  white-space: nowrap;
`,O=i.iK.div`
  .count {
    margin-left: 5px;
    color: ${({theme:e})=>e.colors.primary.base};
    text-decoration: underline;
    cursor: pointer;
  }
`,R=i.iK.div`
  color: ${({theme:e})=>e.colors.grayscale.dark2};
`,j=(0,i.iK)(m.Z)`
  text-align: left;
  font-family: ${({theme:e})=>e.typography.families.monospace};
`,B=(0,h.ZP)((function({addDangerToast:e}){const{state:{loading:t,resourceCount:a,resourceCollection:u},fetchData:h}=(0,p.Yi)("query",(0,l.t)("Query history"),e,!1),[m,x]=(0,r.useState)(),q=(0,i.Fg)(),$=(0,s.k6)(),T=(0,r.useCallback)((t=>{n.Z.get({endpoint:`/api/v1/query/${t}`}).then((({json:e={}})=>{x({...e.result})}),(0,g.v$)((t=>e((0,l.t)("There was an issue previewing the selected query. %s",t)))))}),[e]),D={activeChild:"Query history",...Z.Y},L=[{id:k.J.start_time,desc:!0}],z=(0,r.useMemo)((()=>[{Cell:({row:{original:{status:e}}})=>{const t={name:null,label:""};return e===c.Tb.SUCCESS?(t.name=(0,_.tZ)(C.Z.Check,{iconColor:q.colors.success.base}),t.label=(0,l.t)("Success")):e===c.Tb.FAILED||e===c.Tb.STOPPED?(t.name=(0,_.tZ)(C.Z.XSmall,{iconColor:e===c.Tb.FAILED?q.colors.error.base:q.colors.grayscale.base}),t.label=(0,l.t)("Failed")):e===c.Tb.RUNNING?(t.name=(0,_.tZ)(C.Z.Running,{iconColor:q.colors.primary.base}),t.label=(0,l.t)("Running")):e===c.Tb.TIMED_OUT?(t.name=(0,_.tZ)(C.Z.Offline,{iconColor:q.colors.grayscale.light1}),t.label=(0,l.t)("Offline")):e!==c.Tb.SCHEDULED&&e!==c.Tb.PENDING||(t.name=(0,_.tZ)(C.Z.Queued,{iconColor:q.colors.grayscale.base}),t.label=(0,l.t)("Scheduled")),(0,_.tZ)(f.u,{title:t.label,placement:"bottom"},(0,_.tZ)("span",null,t.name))},accessor:k.J.status,size:"xs",disableSortBy:!0},{accessor:k.J.start_time,Header:(0,l.t)("Time"),size:"xl",Cell:({row:{original:{start_time:e}}})=>{const t=d().utc(e).local().format(w.v2).split(" ");return(0,_.tZ)(r.Fragment,null,t[0]," ",(0,_.tZ)("br",null),t[1])}},{Header:(0,l.t)("Duration"),size:"xl",Cell:({row:{original:{status:e,start_time:t,end_time:a}}})=>{const r=e===c.Tb.FAILED?"danger":e,s=a?d()(d().utc(a-t)).format(w.n2):"00:00:00.000";return(0,_.tZ)(j,{type:r,role:"timer"},s)}},{accessor:k.J.tab_name,Header:(0,l.t)("Tab name"),size:"xl"},{accessor:k.J.database_name,Header:(0,l.t)("Project"),size:"xl"},{accessor:k.J.database,hidden:!0},{accessor:k.J.schema,Header:(0,l.t)("Schema"),size:"xl"},{Cell:({row:{original:{sql_tables:e=[]}}})=>{const t=e.map((e=>e.table)),a=t.length>0?t.shift():"";return t.length?(0,_.tZ)(O,null,(0,_.tZ)("span",null,a),(0,_.tZ)(y.Z,{placement:"right",title:(0,l.t)("TABLES"),trigger:"click",content:(0,_.tZ)(r.Fragment,null,t.map((e=>(0,_.tZ)(R,{key:e},e))))},(0,_.tZ)("span",{className:"count"},"(+",t.length,")"))):a},accessor:k.J.sql_tables,Header:(0,l.t)("Tables"),size:"xl",disableSortBy:!0},{accessor:k.J.user_first_name,Header:(0,l.t)("User"),size:"xl",Cell:({row:{original:{user:e}}})=>(0,J.Z)(e)},{accessor:k.J.user,hidden:!0},{accessor:k.J.rows,Header:(0,l.t)("Rows"),size:"md"},{accessor:k.J.sql,Header:(0,l.t)("SQL"),Cell:({row:{original:e,id:t}})=>(0,_.tZ)("div",{tabIndex:0,role:"button",onClick:()=>x(e)},(0,_.tZ)(F,{language:"sql",style:S.Z},(0,g.IB)(e.sql,4)))},{Header:(0,l.t)("Actions"),id:"actions",disableSortBy:!0,Cell:({row:{original:{id:e}}})=>(0,_.tZ)(f.u,{title:(0,l.t)("Open query in SQL Lab"),placement:"bottom"},(0,_.tZ)(o.rU,{to:`/sqllab?queryId=${e}`},(0,_.tZ)(C.Z.Full,{iconColor:q.colors.grayscale.base})))}]),[]),H=(0,r.useMemo)((()=>[{Header:(0,l.t)("Project"),key:"database",id:"database",input:"select",operator:v.p.relationOneMany,unfilteredLabel:(0,l.t)("All"),fetchSelects:(0,g.tm)("query","database",(0,g.v$)((t=>e((0,l.t)("An error occurred while fetching database values: %s",t))))),paginate:!0},{Header:(0,l.t)("State"),key:"state",id:"status",input:"select",operator:v.p.equals,unfilteredLabel:"All",fetchSelects:(0,g.wk)("query","status",(0,g.v$)((t=>e((0,l.t)("An error occurred while fetching schema values: %s",t))))),paginate:!0},{Header:(0,l.t)("User"),key:"user",id:"user",input:"select",operator:v.p.relationOneMany,unfilteredLabel:"All",fetchSelects:(0,g.tm)("query","user",(0,g.v$)((t=>e((0,l.t)("An error occurred while fetching user values: %s",t))))),paginate:!0},{Header:(0,l.t)("Time range"),key:"start_time",id:"start_time",input:"datetime_range",operator:v.p.between},{Header:(0,l.t)("Search by query text"),key:"sql",id:"sql",input:"search",operator:v.p.contains}]),[e]);return(0,_.tZ)(r.Fragment,null,(0,_.tZ)(b.Z,D),m&&(0,_.tZ)(Q,{onHide:()=>x(void 0),query:m,queries:u,fetchData:T,openInSqlLab:e=>$.push(`/sqllab?queryId=${e}`),show:!0}),(0,_.tZ)(N,{className:"query-history-list-view",columns:z,count:a,data:u,fetchData:h,filters:H,initialSort:L,loading:t,pageSize:25,highlightRowId:null==m?void 0:m.id,refreshData:()=>{},addDangerToast:e,addSuccessToast:E.ws}))}))},83379:(e,t,a)=>{function r(e){return e?`${e.first_name} ${e.last_name}`:""}a.d(t,{Z:()=>r})}}]);
//# sourceMappingURL=d723215b03f05bc2a3e3.chunk.js.map