"use strict";(globalThis.webpackChunksuperset=globalThis.webpackChunksuperset||[]).push([[1611],{129848:(t,e,n)=>{n.d(e,{Z:()=>d}),n(667294);var a=n(751995),o=n(358593),l=n(313322),s=n(211965);const i=a.iK.span`
  white-space: nowrap;
  min-width: 100px;
  svg,
  i {
    margin-right: 8px;

    &:hover {
      path {
        fill: ${({theme:t})=>t.colors.primary.base};
      }
    }
  }
`,r=a.iK.span`
  color: ${({theme:t})=>t.colors.grayscale.base};
`;function d({actions:t}){return(0,s.tZ)(i,{className:"actions"},t.map(((t,e)=>{const n=l.Z[t.icon];return t.tooltip?(0,s.tZ)(o.u,{id:`${t.label}-tooltip`,title:t.tooltip,placement:t.placement,key:e},(0,s.tZ)(r,{role:"button",tabIndex:0,className:"action-button",onClick:t.onClick},(0,s.tZ)(n,null))):(0,s.tZ)(r,{role:"button",tabIndex:0,className:"action-button",onClick:t.onClick,key:e},(0,s.tZ)(n,null))})))}},598217:(t,e,n)=>{n.r(e),n.d(e,{default:()=>N});var a=n(667294),o=n(616550),l=n(473727),s=n(751995),i=n(211965),r=n(61988),d=n(431069),c=n(730381),u=n.n(c),m=n(115926),h=n.n(m),p=n(129848),g=n(419259),Z=n(217198),_=n(593139),b=n(586074),f=n(998286),y=n(414114),x=n(34858),v=n(440768),$=n(662276),w=n(313322),k=n(774069),S=n(794670);const C=s.iK.div`
  margin: ${({theme:t})=>2*t.gridUnit}px auto
    ${({theme:t})=>4*t.gridUnit}px auto;
`,D=(0,s.iK)(S.Ad)`
  border-radius: ${({theme:t})=>t.borderRadius}px;
  border: 1px solid ${({theme:t})=>t.colors.secondary.light2};
`,A=s.iK.div`
  margin-bottom: ${({theme:t})=>5*t.gridUnit}px;

  .control-label {
    margin-bottom: ${({theme:t})=>2*t.gridUnit}px;
  }

  .required {
    margin-left: ${({theme:t})=>t.gridUnit/2}px;
    color: ${({theme:t})=>t.colors.error.base};
  }

  textarea {
    flex: 1 1 auto;
    height: ${({theme:t})=>17*t.gridUnit}px;
    resize: none;
    width: 100%;
  }

  textarea,
  input[type='text'] {
    padding: ${({theme:t})=>1.5*t.gridUnit}px
      ${({theme:t})=>2*t.gridUnit}px;
    border: 1px solid ${({theme:t})=>t.colors.grayscale.light2};
    border-radius: ${({theme:t})=>t.gridUnit}px;
  }

  input[type='text'] {
    width: 65%;
  }
`,T=(0,y.ZP)((({addDangerToast:t,addSuccessToast:e,annotationLayerId:n,annotation:o=null,onAnnotationAdd:l,onHide:s,show:d})=>{var c,m;const[h,p]=(0,a.useState)(!0),[g,Z]=(0,a.useState)(null),_=null!==o,{state:{loading:b,resource:f},fetchResource:y,createResource:S,updateResource:T}=(0,x.LE)(`annotation_layer/${n}/annotation`,(0,r.t)("annotation"),t),H=()=>{Z({short_descr:"",start_dttm:"",end_dttm:"",json_metadata:"",long_descr:""})},N=()=>{_?Z(f):H(),s()},E=t=>{const{target:e}=t,n={...g,end_dttm:g?g.end_dttm:"",short_descr:g?g.short_descr:"",start_dttm:g?g.start_dttm:""};n[e.name]=e.value,Z(n)};return(0,a.useEffect)((()=>{if(_&&(null==g||!g.id||o&&o.id!==g.id||d)){if(null!==(null==o?void 0:o.id)&&!b){const t=o.id||0;y(t)}}else _||g&&!g.id&&!d||H()}),[o]),(0,a.useEffect)((()=>{f&&Z(f)}),[f]),(0,a.useEffect)((()=>{var t,e,n;null!=g&&null!=(t=g.short_descr)&&t.length&&null!=g&&null!=(e=g.start_dttm)&&e.length&&null!=g&&null!=(n=g.end_dttm)&&n.length?p(!1):p(!0)}),[g?g.short_descr:"",g?g.start_dttm:"",g?g.end_dttm:""]),(0,i.tZ)(k.default,{disablePrimaryButton:h,onHandledPrimaryAction:()=>{if(_){if(null!=g&&g.id){const t=g.id;delete g.id,delete g.created_by,delete g.changed_by,delete g.changed_on_delta_humanized,delete g.layer,T(t,g).then((t=>{t&&(l&&l(),N(),e((0,r.t)("The annotation has been updated")))}))}}else g&&S(g).then((t=>{t&&(l&&l(),N(),e((0,r.t)("The annotation has been saved")))}))},onHide:N,primaryButtonName:_?(0,r.t)("Save"):(0,r.t)("Add"),show:d,width:"55%",title:(0,i.tZ)("h4",null,_?(0,i.tZ)(w.Z.EditAlt,{css:v.xL}):(0,i.tZ)(w.Z.PlusLarge,{css:v.xL}),_?(0,r.t)("Edit annotation"):(0,r.t)("Add annotation"))},(0,i.tZ)(C,null,(0,i.tZ)("h4",null,(0,r.t)("Basic information"))),(0,i.tZ)(A,null,(0,i.tZ)("div",{className:"control-label"},(0,r.t)("Name"),(0,i.tZ)("span",{className:"required"},"*")),(0,i.tZ)("input",{name:"short_descr",onChange:E,type:"text",value:null==g?void 0:g.short_descr})),(0,i.tZ)(A,null,(0,i.tZ)("div",{className:"control-label"},(0,r.t)("date"),(0,i.tZ)("span",{className:"required"},"*")),(0,i.tZ)($.S,{placeholder:[(0,r.t)("Start date"),(0,r.t)("End date")],format:"YYYY-MM-DD HH:mm",onChange:(t,e)=>{const n={...g,end_dttm:g&&e[1].length?u()(e[1]).format("YYYY-MM-DD HH:mm"):"",short_descr:g?g.short_descr:"",start_dttm:g&&e[0].length?u()(e[0]).format("YYYY-MM-DD HH:mm"):""};Z(n)},showTime:{format:"hh:mm a"},use12Hours:!0,value:null!=g&&null!=(c=g.start_dttm)&&c.length||null!=g&&null!=(m=g.end_dttm)&&m.length?[u()(g.start_dttm),u()(g.end_dttm)]:null})),(0,i.tZ)(C,null,(0,i.tZ)("h4",null,(0,r.t)("Additional information"))),(0,i.tZ)(A,null,(0,i.tZ)("div",{className:"control-label"},(0,r.t)("description")),(0,i.tZ)("textarea",{name:"long_descr",value:g?g.long_descr:"",placeholder:(0,r.t)("Description (this can be seen in the list)"),onChange:E})),(0,i.tZ)(A,null,(0,i.tZ)("div",{className:"control-label"},(0,r.t)("JSON metadata")),(0,i.tZ)(D,{onChange:t=>{const e={...g,end_dttm:g?g.end_dttm:"",json_metadata:t,short_descr:g?g.short_descr:"",start_dttm:g?g.start_dttm:""};Z(e)},value:null!=g&&g.json_metadata?g.json_metadata:"",width:"100%",height:"120px"})))})),H=s.iK.div`
  ${({theme:t})=>i.iv`
    display: flex;
    flex-direction: row;

    a,
    Link {
      margin-left: ${4*t.gridUnit}px;
      font-size: ${t.typography.sizes.s}px;
      font-weight: ${t.typography.weights.normal};
      text-decoration: underline;
    }
  `}
`,N=(0,y.ZP)((function({addDangerToast:t,addSuccessToast:e}){const{annotationLayerId:n}=(0,o.UO)(),{state:{loading:s,resourceCount:c,resourceCollection:m,bulkSelectEnabled:y},fetchData:$,refreshData:w,toggleBulkSelect:k}=(0,x.Yi)(`annotation_layer/${n}/annotation`,(0,r.t)("annotation"),t,!1),[S,C]=(0,a.useState)(!1),[D,A]=(0,a.useState)(""),[N,E]=(0,a.useState)(null),[Y,U]=(0,a.useState)(null),B=t=>{E(t),C(!0)},L=(0,a.useCallback)((async function(){try{const t=await d.Z.get({endpoint:`/api/v1/annotation_layer/${n}`});A(t.json.result.name)}catch(e){await(0,f.O$)(e).then((({error:e})=>{t(e.error||e.statusText||e)}))}}),[n]);(0,a.useEffect)((()=>{L()}),[L]);const M=[{id:"short_descr",desc:!0}],j=(0,a.useMemo)((()=>[{accessor:"short_descr",Header:(0,r.t)("Name")},{accessor:"long_descr",Header:(0,r.t)("Description")},{Cell:({row:{original:{start_dttm:t}}})=>u()(new Date(t)).format("ll"),Header:(0,r.t)("Start"),accessor:"start_dttm"},{Cell:({row:{original:{end_dttm:t}}})=>u()(new Date(t)).format("ll"),Header:(0,r.t)("End"),accessor:"end_dttm"},{Cell:({row:{original:t}})=>{const e=[{label:"edit-action",tooltip:(0,r.t)("Edit annotation"),placement:"bottom",icon:"Edit",onClick:()=>B(t)},{label:"delete-action",tooltip:(0,r.t)("Delete annotation"),placement:"bottom",icon:"Trash",onClick:()=>U(t)}];return(0,i.tZ)(p.Z,{actions:e})},Header:(0,r.t)("Actions"),id:"actions",disableSortBy:!0}]),[!0,!0]),K=[];K.push({name:(0,i.tZ)(a.Fragment,null,(0,i.tZ)("i",{className:"fa fa-plus"})," ",(0,r.t)("Annotation")),buttonStyle:"primary",onClick:()=>{B(null)}}),K.push({name:(0,r.t)("Bulk select"),onClick:k,buttonStyle:"secondary","data-test":"annotation-bulk-select"});let P=!0;try{(0,o.k6)()}catch(t){P=!1}const z={title:(0,r.t)("No annotation yet"),image:"filter-results.svg",buttonAction:()=>{B(null)},buttonText:(0,i.tZ)(a.Fragment,null,(0,i.tZ)("i",{className:"fa fa-plus"})," ",(0,r.t)("Annotation"))};return(0,i.tZ)(a.Fragment,null,(0,i.tZ)(b.Z,{name:(0,i.tZ)(H,null,(0,i.tZ)("span",null,(0,r.t)("Annotation Layer %s",D)),(0,i.tZ)("span",null,P?(0,i.tZ)(l.rU,{to:"/annotationlayer/list/"},(0,r.t)("Back to all")):(0,i.tZ)("a",{href:"/annotationlayer/list/"},(0,r.t)("Back to all")))),buttons:K}),(0,i.tZ)(T,{addDangerToast:t,addSuccessToast:e,annotation:N,show:S,onAnnotationAdd:()=>w(),annotationLayerId:n,onHide:()=>C(!1)}),Y&&(0,i.tZ)(Z.Z,{description:(0,r.t)("Are you sure you want to delete %s?",null==Y?void 0:Y.short_descr),onConfirm:()=>{Y&&(({id:a,short_descr:o})=>{d.Z.delete({endpoint:`/api/v1/annotation_layer/${n}/annotation/${a}`}).then((()=>{w(),U(null),e((0,r.t)("Deleted: %s",o))}),(0,v.v$)((e=>t((0,r.t)("There was an issue deleting %s: %s",o,e)))))})(Y)},onHide:()=>U(null),open:!0,title:(0,r.t)("Delete Annotation?")}),(0,i.tZ)(g.Z,{title:(0,r.t)("Please confirm"),description:(0,r.t)("Are you sure you want to delete the selected annotations?"),onConfirm:a=>{d.Z.delete({endpoint:`/api/v1/annotation_layer/${n}/annotation/?q=${h().encode(a.map((({id:t})=>t)))}`}).then((({json:t={}})=>{w(),e(t.message)}),(0,v.v$)((e=>t((0,r.t)("There was an issue deleting the selected annotations: %s",e)))))}},(n=>{const a=[{key:"delete",name:(0,r.t)("Delete"),onSelect:n,type:"danger"}];return(0,i.tZ)(_.Z,{className:"annotations-list-view",bulkActions:a,bulkSelectEnabled:y,columns:j,count:c,data:m,disableBulkSelect:k,emptyState:z,fetchData:$,addDangerToast:t,addSuccessToast:e,refreshData:w,initialSort:M,loading:s,pageSize:25})})))}))}}]);
//# sourceMappingURL=7dc649c9c1b63da11f56.chunk.js.map