"use strict";(globalThis.webpackChunksuperset=globalThis.webpackChunksuperset||[]).push([[7001],{281788:(e,t,a)=>{a.d(t,{B8:()=>d,TZ:()=>o,mf:()=>l,u7:()=>r});var s=a(431069),n=a(68492);const i=(e,t,a)=>{let s=`api/v1/dashboard/${e}/filter_state`;return t&&(s=s.concat(`/${t}`)),a&&(s=s.concat(`?tab_id=${a}`)),s},o=(e,t,a,o)=>s.Z.put({endpoint:i(e,a,o),jsonPayload:{value:t}}).then((e=>e.json.message)).catch((e=>(n.Z.error(e),null))),r=(e,t,a)=>s.Z.post({endpoint:i(e,void 0,a),jsonPayload:{value:t}}).then((e=>e.json.key)).catch((e=>(n.Z.error(e),null))),d=(e,t)=>s.Z.get({endpoint:i(e,t)}).then((({json:e})=>JSON.parse(e.value))).catch((e=>(n.Z.error(e),null))),l=e=>s.Z.get({endpoint:`/api/v1/dashboard/permalink/${e}`}).then((({json:e})=>e)).catch((e=>(n.Z.error(e),null)))},257001:(e,t,a)=>{a.r(t),a.d(t,{DashboardPage:()=>oe,DashboardPageIdContext:()=>se,default:()=>re});var s=a(667294),n=a(211965),i=a(616550),o=a(751995),r=a(593185),d=a(478161),l=a(328062),c=a(61988),u=a(828216),p=a(414114),h=a(838703),m=a(367417),g=a(904305),f=a(550810),v=a(514505),b=a(961337),y=a(427600),w=a(23525),_=a(152794),S=a(909467),E=a(281788),x=a(14890),D=a(45697),C=a.n(D),T=a(514278),I=a(920292),R=a(81255);function j(e){return Object.values(e).reduce(((e,t)=>(t&&t.type===R.dW&&t.meta&&t.meta.chartId&&e.push(t.meta.chartId),e)),[])}var F=a(602275),O=a(203741),$=a(599543),U=a(156967);const Z=[R.dW,R.xh,R.t];function k(e){return!Object.values(e).some((({type:e})=>e&&Z.includes(e)))}const q={actions:C().shape({addSliceToDashboard:C().func.isRequired,removeSliceFromDashboard:C().func.isRequired,triggerQuery:C().func.isRequired,logEvent:C().func.isRequired,clearDataMaskState:C().func.isRequired}).isRequired,dashboardInfo:F.$X.isRequired,dashboardState:F.DZ.isRequired,slices:C().objectOf(F.Rw).isRequired,activeFilters:C().object.isRequired,chartConfiguration:C().object,datasources:C().object.isRequired,ownDataCharts:C().object.isRequired,layout:C().object.isRequired,impressionId:C().string.isRequired,timeout:C().number,userId:C().string};class L extends s.PureComponent{static onBeforeUnload(e){e?window.addEventListener("beforeunload",L.unload):window.removeEventListener("beforeunload",L.unload)}static unload(){const e=(0,c.t)("You have unsaved changes.");return window.event.returnValue=e,e}constructor(e){var t,a;super(e),this.appliedFilters=null!=(t=e.activeFilters)?t:{},this.appliedOwnDataCharts=null!=(a=e.ownDataCharts)?a:{},this.onVisibilityChange=this.onVisibilityChange.bind(this)}componentDidMount(){const e=(0,I.Z)(),{dashboardState:t,layout:a}=this.props,s={is_soft_navigation:O.Yd.timeOriginOffset>0,is_edit_mode:t.editMode,mount_duration:O.Yd.getTimestamp(),is_empty:k(a),is_published:t.isPublished,bootstrap_data_length:e.length},n=(0,U.Z)();n&&(s.target_id=n),this.props.actions.logEvent(O.Wl,s),"hidden"===document.visibilityState&&(this.visibilityEventData={start_offset:O.Yd.getTimestamp(),ts:(new Date).getTime()}),window.addEventListener("visibilitychange",this.onVisibilityChange),this.applyCharts()}componentDidUpdate(){this.applyCharts()}UNSAFE_componentWillReceiveProps(e){const t=j(this.props.layout),a=j(e.layout);this.props.dashboardInfo.id===e.dashboardInfo.id&&(t.length<a.length?a.filter((e=>-1===t.indexOf(e))).forEach((t=>{return this.props.actions.addSliceToDashboard(t,(a=e.layout,s=t,Object.values(a).find((e=>e&&e.type===R.dW&&e.meta&&e.meta.chartId===s))));var a,s})):t.length>a.length&&t.filter((e=>-1===a.indexOf(e))).forEach((e=>this.props.actions.removeSliceFromDashboard(e))))}applyCharts(){const{hasUnsavedChanges:e,editMode:t}=this.props.dashboardState,{appliedFilters:a,appliedOwnDataCharts:s}=this,{activeFilters:n,ownDataCharts:i,chartConfiguration:o}=this.props;(0,r.cr)(r.TT.DASHBOARD_CROSS_FILTERS)&&!o||(t||(0,$.JB)(s,i,{ignoreUndefined:!0})&&(0,$.JB)(a,n,{ignoreUndefined:!0})||this.applyFilters(),e?L.onBeforeUnload(!0):L.onBeforeUnload(!1))}componentWillUnmount(){window.removeEventListener("visibilitychange",this.onVisibilityChange),this.props.actions.clearDataMaskState()}onVisibilityChange(){if("hidden"===document.visibilityState)this.visibilityEventData={start_offset:O.Yd.getTimestamp(),ts:(new Date).getTime()};else if("visible"===document.visibilityState){const e=this.visibilityEventData.start_offset;this.props.actions.logEvent(O.Ev,{...this.visibilityEventData,duration:O.Yd.getTimestamp()-e})}}applyFilters(){const{appliedFilters:e}=this,{activeFilters:t,ownDataCharts:a}=this.props,s=Object.keys(t),n=Object.keys(e),i=new Set(s.concat(n)),o=((e,t)=>{const a=Object.keys(e),s=Object.keys(t),n=(i=a,o=s,[...i.filter((e=>!o.includes(e))),...o.filter((e=>!i.includes(e)))]).filter((a=>e[a]||t[a]));var i,o;return new Set([...a,...s]).forEach((a=>{(0,$.JB)(e[a],t[a])||n.push(a)})),[...new Set(n)]})(a,this.appliedOwnDataCharts);[...i].forEach((a=>{if(!s.includes(a)&&n.includes(a))o.push(...e[a].scope);else if(n.includes(a)){if((0,$.JB)(e[a].values,t[a].values,{ignoreUndefined:!0})||o.push(...t[a].scope),!(0,$.JB)(e[a].scope,t[a].scope)){const s=(t[a].scope||[]).concat(e[a].scope||[]);o.push(...s)}}else o.push(...t[a].scope)})),this.refreshCharts([...new Set(o)]),this.appliedFilters=t,this.appliedOwnDataCharts=a}refreshCharts(e){e.forEach((e=>{this.props.actions.triggerQuery(!0,e)}))}render(){return this.context.loading?(0,n.tZ)(h.Z,null):this.props.children}}L.contextType=T.Zn,L.propTypes=q,L.defaultProps={timeout:60,userId:""};const B=L;var P=a(452256),M=a(797381),J=a(643399),N=a(987915),V=a(174599);const A=(0,u.$j)((function(e){var t,a,s,n;const{datasources:i,sliceEntities:o,dataMask:r,dashboardInfo:d,dashboardState:l,dashboardLayout:c,impressionId:u,nativeFilters:p}=e;return{timeout:null==(t=d.common)||null==(a=t.conf)?void 0:a.SUPERSET_WEBSERVER_TIMEOUT,userId:d.userId,dashboardInfo:d,dashboardState:l,datasources:i,activeFilters:{...(0,J.De)(),...(0,N.g)({chartConfiguration:null==(s=d.metadata)?void 0:s.chart_configuration,nativeFilters:p.filters,dataMask:r,allSliceIds:l.sliceIds})},chartConfiguration:null==(n=d.metadata)?void 0:n.chart_configuration,ownDataCharts:(0,N.U)(r,"ownState"),slices:o.slices,layout:c.present,impressionId:u}}),(function(e){return{actions:(0,x.DE)({setDatasources:f.Fy,clearDataMaskState:V.sh,addSliceToDashboard:S.Pi,removeSliceFromDashboard:S.rL,triggerQuery:P.triggerQuery,logEvent:M.logEvent},e)}}))(B);var Y=a(714670),Q=a.n(Y);const z=e=>n.iv`
  body {
    h1 {
      font-weight: ${e.typography.weights.bold};
      line-height: 1.4;
      font-size: ${e.typography.sizes.xxl}px;
      letter-spacing: -0.2px;
      margin-top: ${3*e.gridUnit}px;
      margin-bottom: ${3*e.gridUnit}px;
    }

    h2 {
      font-weight: ${e.typography.weights.bold};
      line-height: 1.4;
      font-size: ${e.typography.sizes.xl}px;
      margin-top: ${3*e.gridUnit}px;
      margin-bottom: ${2*e.gridUnit}px;
    }

    h3,
    h4,
    h5,
    h6 {
      font-weight: ${e.typography.weights.bold};
      line-height: 1.4;
      font-size: ${e.typography.sizes.l}px;
      letter-spacing: 0.2px;
      margin-top: ${2*e.gridUnit}px;
      margin-bottom: ${e.gridUnit}px;
    }
  }
`,W=e=>n.iv`
  .filter-card-popover {
    width: 240px;
    padding: 0;
    border-radius: 4px;

    &.ant-popover-placement-bottom {
      padding-top: ${e.gridUnit}px;
    }

    &.ant-popover-placement-left {
      padding-right: ${3*e.gridUnit}px;
    }

    .ant-popover-inner {
      box-shadow: 0 0 8px rgb(0 0 0 / 10%);
    }

    .ant-popover-inner-content {
      padding: ${4*e.gridUnit}px;
    }

    .ant-popover-arrow {
      display: none;
    }
  }

  .filter-card-tooltip {
    &.ant-tooltip-placement-bottom {
      padding-top: 0;
      & .ant-tooltip-arrow {
        top: -13px;
      }
    }
  }
`,K=e=>n.iv`
  .ant-dropdown-menu.chart-context-menu {
    min-width: ${43*e.gridUnit}px;
  }
  .ant-dropdown-menu-submenu.chart-context-submenu {
    max-width: ${60*e.gridUnit}px;
    min-width: ${40*e.gridUnit}px;
  }
`;var H=a(478718),X=a.n(H);const G={},ee=()=>{const e=(0,b.rV)(b.dR.dashboard__explore_context,{});return Object.fromEntries(Object.entries(e).filter((([,e])=>!e.isRedundant)))},te=(e,t)=>{const a=ee();(0,b.LS)(b.dR.dashboard__explore_context,{...a,[e]:t})},ae=({dashboardPageId:e})=>{const t=(0,u.v9)((({dashboardInfo:t,dashboardState:a,nativeFilters:s,dataMask:n})=>{var i,o,r;return{labelColors:(null==(i=t.metadata)?void 0:i.label_colors)||G,sharedLabelColors:(null==(o=t.metadata)?void 0:o.shared_label_colors)||G,colorScheme:null==a?void 0:a.colorScheme,chartConfiguration:(null==(r=t.metadata)?void 0:r.chart_configuration)||G,nativeFilters:Object.entries(s.filters).reduce(((e,[t,a])=>({...e,[t]:X()(a,["chartsInScope"])})),{}),dataMask:n,dashboardId:t.id,filterBoxFilters:(0,J.De)(),dashboardPageId:e}}),u.wU);return(0,s.useEffect)((()=>(te(e,t),()=>{te(e,{...t,isRedundant:!0})})),[t,e]),null},se=s.createContext(""),ne=s.lazy((()=>Promise.all([a.e(1216),a.e(9612),a.e(876),a.e(981),a.e(9258),a.e(5640),a.e(3197),a.e(95),a.e(868),a.e(1880),a.e(8149),a.e(4717),a.e(452)]).then(a.bind(a,179701)))),ie=document.title,oe=({idOrSlug:e})=>{const t=(0,o.Fg)(),a=(0,u.I0)(),x=(0,i.k6)(),D=(0,s.useMemo)((()=>Q().generate()),[]),C=(0,u.v9)((({dashboardInfo:e})=>e&&Object.keys(e).length>0)),{addDangerToast:T}=(0,p.e1)(),{result:I,error:R}=(0,m.QU)(e),{result:j,error:F}=(0,m.Es)(e),{result:O,error:$,status:U}=(0,m.JL)(e),Z=(0,s.useRef)(!1),k=R||F,q=Boolean(I&&j),{dashboard_title:L,css:B,metadata:P,id:M=0}=I||{},J=(0,r.cr)(r.TT.DASHBOARD_NATIVE_FILTERS_SET)&&(0,r.cr)(r.TT.DASHBOARD_NATIVE_FILTERS);if((0,s.useEffect)((()=>{const e=()=>{const e=ee();(0,b.LS)(b.dR.dashboard__explore_context,{...e,[D]:{...e[D],isRedundant:!0}})};return window.addEventListener("beforeunload",e),()=>{window.removeEventListener("beforeunload",e)}}),[D]),(0,s.useEffect)((()=>{a((0,S.sL)(U))}),[a,U]),(0,s.useEffect)((()=>{M&&async function(){const e=(0,w.eY)(y.KD.permalinkKey),t=(0,w.eY)(y.KD.nativeFiltersKey),s=(0,w.eY)(y.KD.nativeFilters);let n,i=t||{};if(e){const t=await(0,E.mf)(e);t&&({dataMask:i,activeTabs:n}=t.state)}else t&&(i=await(0,E.B8)(M,t));s&&(i=s),q&&(Z.current||(Z.current=!0,J&&a((0,_.pi)(M))),a((0,g.Y)({history:x,dashboard:I,charts:j,activeTabs:n,dataMask:i})))}()}),[q]),(0,s.useEffect)((()=>(L&&(document.title=L),()=>{document.title=ie})),[L]),(0,s.useEffect)((()=>"string"==typeof B?(0,v.Z)(B):()=>{}),[B]),(0,s.useEffect)((()=>{const e=(0,d.ZP)();return e.source=d.Ag.dashboard,()=>{l.getNamespace(null==P?void 0:P.color_namespace).resetColors(),e.clear()}}),[null==P?void 0:P.color_namespace]),(0,s.useEffect)((()=>{$?T((0,c.t)("Error loading chart datasources. Filters may not work correctly.")):a((0,f.Fy)(O))}),[T,O,$,a]),k)throw k;return q&&C?(0,n.tZ)(s.Fragment,null,(0,n.tZ)(n.xB,{styles:[W(t),z(t),K(t),"",""]}),(0,n.tZ)(ae,{dashboardPageId:D}),(0,n.tZ)(se.Provider,{value:D},(0,n.tZ)(A,null,(0,n.tZ)(ne,null)))):(0,n.tZ)(h.Z,null)},re=oe},987915:(e,t,a)=>{a.d(t,{U:()=>s,g:()=>n});const s=(e,t)=>Object.values(e).filter((e=>e[t])).reduce(((e,a)=>({...e,[a.id]:t?a[t]:a})),{}),n=({chartConfiguration:e,nativeFilters:t,dataMask:a,allSliceIds:s})=>{const n={};return Object.values(a).forEach((({id:a,extraFormData:i})=>{var o,r,d,l,c,u;const p=null!=(o=null!=(r=null!=(d=null==t||null==(l=t[a])?void 0:l.chartsInScope)?d:null==e||null==(c=e[a])||null==(u=c.crossFilters)?void 0:u.chartsInScope)?r:s)?o:[];n[a]={scope:p,values:i}})),n}},514505:(e,t,a)=>{function s(e){const t="CssEditor-css",a=document.head||document.getElementsByTagName("head")[0],s=document.querySelector(`.${t}`)||function(e){const t=document.createElement("style");return t.className=e,t.type="text/css",t}(t);return"styleSheet"in s?s.styleSheet.cssText=e:s.innerHTML=e,a.appendChild(s),function(){s.remove()}}a.d(t,{Z:()=>s})},367417:(e,t,a)=>{a.d(t,{schemaEndpoints:()=>h.Kt,CN:()=>s.CN,tableEndpoints:()=>p.QD,hb:()=>d,QU:()=>l,Es:()=>c,JL:()=>u,L8:()=>g,Xx:()=>h.Xx,SJ:()=>p.SJ,uY:()=>p.uY,zA:()=>p.zA});var s=a(845673),n=a(242190),i=a(115926);function o({owners:e}){return e?e.map((e=>`${e.first_name} ${e.last_name}`)):null}const r=a.n(i)().encode({columns:["owners.first_name","owners.last_name"],keys:["none"]});function d(e){return(0,n.l6)((0,n.s_)(`/api/v1/chart/${e}?q=${r}`),o)}const l=e=>(0,n.l6)((0,n.s_)(`/api/v1/dashboard/${e}`),(e=>({...e,metadata:e.json_metadata&&JSON.parse(e.json_metadata)||{},position_data:e.position_json&&JSON.parse(e.position_json),owners:e.owners||[]}))),c=e=>(0,n.s_)(`/api/v1/dashboard/${e}/charts`),u=e=>(0,n.s_)(`/api/v1/dashboard/${e}/datasets`);var p=a(123936),h=a(469279);const m=a(610362).h.injectEndpoints({endpoints:e=>({queryValidations:e.query({providesTags:["QueryValidations"],query:({dbId:e,schema:t,sql:a,templateParams:s})=>{let n=s;try{n=JSON.parse(s||"")}catch(e){n=void 0}const i={schema:t,sql:a,...n&&{template_params:n}};return{method:"post",endpoint:`/api/v1/database/${e}/validate_sql/`,headers:{"Content-Type":"application/json"},body:JSON.stringify(i),transformResponse:({json:e})=>e.result}}})})}),{useQueryValidationsQuery:g}=m}}]);
//# sourceMappingURL=210db7f02702ecf87892.chunk.js.map