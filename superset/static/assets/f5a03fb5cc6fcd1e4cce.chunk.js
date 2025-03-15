"use strict";(globalThis.webpackChunksuperset=globalThis.webpackChunksuperset||[]).push([[906],{554070:(e,t,a)=>{a.d(t,{w:()=>r}),a(667294);var n=a(358593),o=a(83379),l=a(61988),i=a(211965);const r=({user:e,date:t})=>{const a=(0,i.tZ)("span",{className:"no-wrap"},t);if(e){const t=(0,o.Z)(e),r=(0,l.t)("Modified by: %s",t);return(0,i.tZ)(n.u,{title:r,placement:"bottom"},a)}return a}},129848:(e,t,a)=>{a.d(t,{Z:()=>c}),a(667294);var n=a(751995),o=a(358593),l=a(313322),i=a(211965);const r=n.iK.span`
  white-space: nowrap;
  min-width: 100px;
  svg,
  i {
    margin-right: 8px;

    &:hover {
      path {
        fill: ${({theme:e})=>e.colors.primary.base};
      }
    }
  }
`,s=n.iK.span`
  color: ${({theme:e})=>e.colors.grayscale.base};
`;function c({actions:e}){return(0,i.tZ)(r,{className:"actions"},e.map(((e,t)=>{const a=l.Z[e.icon];return e.tooltip?(0,i.tZ)(o.u,{id:`${e.label}-tooltip`,title:e.tooltip,placement:e.placement,key:t},(0,i.tZ)(s,{role:"button",tabIndex:0,className:"action-button",onClick:e.onClick},(0,i.tZ)(a,null))):(0,i.tZ)(s,{role:"button",tabIndex:0,className:"action-button",onClick:e.onClick,key:t},(0,i.tZ)(a,null))})))}},778768:(e,t,a)=>{a.r(t),a.d(t,{default:()=>C});var n=a(667294),o=a(115926),l=a.n(o),i=a(61988),r=a(431069),s=a(616550),c=a(473727),d=a(34858),u=a(440768),m=a(414114),p=a(586074),h=a(129848),g=a(593139),y=a(217198),Z=a(419259),b=a(751995),f=a(313322),w=a(774069),x=a(211965);const v=b.iK.div`
  margin: ${({theme:e})=>2*e.gridUnit}px auto
    ${({theme:e})=>4*e.gridUnit}px auto;
`,k=b.iK.div`
  margin-bottom: ${({theme:e})=>10*e.gridUnit}px;

  .control-label {
    margin-bottom: ${({theme:e})=>2*e.gridUnit}px;
  }

  .required {
    margin-left: ${({theme:e})=>e.gridUnit/2}px;
    color: ${({theme:e})=>e.colors.error.base};
  }

  textarea,
  input[type='text'] {
    padding: ${({theme:e})=>1.5*e.gridUnit}px
      ${({theme:e})=>2*e.gridUnit}px;
    border: 1px solid ${({theme:e})=>e.colors.grayscale.light2};
    border-radius: ${({theme:e})=>e.gridUnit}px;
    width: 50%;
  }

  input,
  textarea {
    flex: 1 1 auto;
  }

  textarea {
    width: 100%;
    height: 160px;
    resize: none;
  }

  input::placeholder,
  textarea::placeholder {
    color: ${({theme:e})=>e.colors.grayscale.light1};
  }
`,$=(0,m.ZP)((({addDangerToast:e,addSuccessToast:t,onLayerAdd:a,onHide:o,show:l,layer:r=null})=>{const[s,c]=(0,n.useState)(!0),[m,p]=(0,n.useState)(),[h,g]=(0,n.useState)(!0),y=null!==r,{state:{loading:Z,resource:b},fetchResource:$,createResource:S,updateResource:_}=(0,d.LE)("annotation_layer",(0,i.t)("annotation_layer"),e),C=()=>{p({name:"",descr:""})},A=()=>{g(!0),C(),o()},D=e=>{const{target:t}=e,a={...m,name:m?m.name:"",descr:m?m.descr:""};a[t.name]=t.value,p(a)};return(0,n.useEffect)((()=>{if(y&&(null==m||!m.id||r&&r.id!==m.id||h&&l)){if(l&&r&&null!==r.id&&!Z){const e=r.id||0;$(e)}}else!y&&(!m||m.id||h&&l)&&C()}),[r,l]),(0,n.useEffect)((()=>{b&&p(b)}),[b]),(0,n.useEffect)((()=>{var e;null!=m&&null!=(e=m.name)&&e.length?c(!1):c(!0)}),[m?m.name:"",m?m.descr:""]),h&&l&&g(!1),(0,x.tZ)(w.default,{disablePrimaryButton:s,onHandledPrimaryAction:()=>{if(y){if(null!=m&&m.id){const e=m.id;delete m.id,delete m.created_by,_(e,m).then((e=>{e&&(A(),t((0,i.t)("Annotation template updated")))}))}}else m&&S(m).then((e=>{e&&(a&&a(e),A(),t((0,i.t)("Annotation template created")))}))},onHide:A,primaryButtonName:y?(0,i.t)("Save"):(0,i.t)("Add"),show:l,width:"55%",title:(0,x.tZ)("h4",null,y?(0,x.tZ)(f.Z.EditAlt,{css:u.xL}):(0,x.tZ)(f.Z.PlusLarge,{css:u.xL}),y?(0,i.t)("Edit annotation layer properties"):(0,i.t)("Add annotation layer"))},(0,x.tZ)(v,null,(0,x.tZ)("h4",null,(0,i.t)("Basic information"))),(0,x.tZ)(k,null,(0,x.tZ)("div",{className:"control-label"},(0,i.t)("Annotation layer name"),(0,x.tZ)("span",{className:"required"},"*")),(0,x.tZ)("input",{name:"name",onChange:D,type:"text",value:null==m?void 0:m.name})),(0,x.tZ)(k,null,(0,x.tZ)("div",{className:"control-label"},(0,i.t)("description")),(0,x.tZ)("textarea",{name:"descr",value:null==m?void 0:m.descr,placeholder:(0,i.t)("Description (this can be seen in the list)"),onChange:D})))}));var S=a(554070),_=a(400012);const C=(0,m.ZP)((function({addDangerToast:e,addSuccessToast:t,user:a}){const{state:{loading:o,resourceCount:m,resourceCollection:b,bulkSelectEnabled:f},hasPerm:w,fetchData:v,refreshData:k,toggleBulkSelect:C}=(0,d.Yi)("annotation_layer",(0,i.t)("Annotation layers"),e),[A,D]=(0,n.useState)(!1),[N,T]=(0,n.useState)(null),[H,E]=(0,n.useState)(null),L=w("can_write"),U=w("can_write"),B=w("can_write");function P(e){T(e),D(!0)}const z=[{id:"name",desc:!0}],K=(0,n.useMemo)((()=>[{accessor:"name",Header:(0,i.t)("Name"),Cell:({row:{original:{id:e,name:t}}})=>{let a=!0;try{(0,s.k6)()}catch(e){a=!1}return a?(0,x.tZ)(c.rU,{to:`/annotationlayer/${e}/annotation`},t):(0,x.tZ)("a",{href:`/annotationlayer/${e}/annotation`},t)}},{accessor:"descr",Header:(0,i.t)("Description")},{Cell:({row:{original:{changed_on_delta_humanized:e,changed_by:t}}})=>(0,x.tZ)(S.w,{date:e,user:t}),Header:(0,i.t)("Last modified"),accessor:"changed_on",size:"xl"},{Cell:({row:{original:e}})=>{const t=[U?{label:"edit-action",tooltip:(0,i.t)("Edit template"),placement:"bottom",icon:"Edit",onClick:()=>P(e)}:null,B?{label:"delete-action",tooltip:(0,i.t)("Delete template"),placement:"bottom",icon:"Trash",onClick:()=>E(e)}:null].filter((e=>!!e));return(0,x.tZ)(h.Z,{actions:t})},Header:(0,i.t)("Actions"),id:"actions",disableSortBy:!0,hidden:!U&&!B,size:"xl"},{accessor:_.J.changed_by,hidden:!0}]),[B,L]),M=[];L&&M.push({name:(0,x.tZ)(n.Fragment,null,(0,x.tZ)("i",{className:"fa fa-plus"})," ",(0,i.t)("Annotation layer")),buttonStyle:"primary",onClick:()=>{P(null)}}),B&&M.push({name:(0,i.t)("Bulk select"),onClick:C,buttonStyle:"secondary"});const q=(0,n.useMemo)((()=>[{Header:(0,i.t)("Name"),key:"search",id:"name",input:"search",operator:g.p.contains},{Header:(0,i.t)("Changed by"),key:"changed_by",id:"changed_by",input:"select",operator:g.p.relationOneMany,unfilteredLabel:(0,i.t)("All"),fetchSelects:(0,u.tm)("annotation_layer","changed_by",(0,u.v$)((e=>(0,i.t)("An error occurred while fetching dataset datasource values: %s",e))),a),paginate:!0}]),[]),F={title:(0,i.t)("No annotation layers yet"),image:"filter-results.svg",buttonAction:()=>P(null),buttonText:(0,x.tZ)(n.Fragment,null,(0,x.tZ)("i",{className:"fa fa-plus"})," ",(0,i.t)("Annotation layer"))};return(0,x.tZ)(n.Fragment,null,(0,x.tZ)(p.Z,{name:(0,i.t)("Annotation layers"),buttons:M}),(0,x.tZ)($,{addDangerToast:e,layer:N,onLayerAdd:e=>{window.location.href=`/annotationlayer/${e}/annotation`},onHide:()=>{k(),D(!1)},show:A}),H&&(0,x.tZ)(y.Z,{description:(0,i.t)("This action will permanently delete the layer."),onConfirm:()=>{H&&(({id:a,name:n})=>{r.Z.delete({endpoint:`/api/v1/annotation_layer/${a}`}).then((()=>{k(),E(null),t((0,i.t)("Deleted: %s",n))}),(0,u.v$)((t=>e((0,i.t)("There was an issue deleting %s: %s",n,t)))))})(H)},onHide:()=>E(null),open:!0,title:(0,i.t)("Delete Layer?")}),(0,x.tZ)(Z.Z,{title:(0,i.t)("Please confirm"),description:(0,i.t)("Are you sure you want to delete the selected layers?"),onConfirm:a=>{r.Z.delete({endpoint:`/api/v1/annotation_layer/?q=${l().encode(a.map((({id:e})=>e)))}`}).then((({json:e={}})=>{k(),t(e.message)}),(0,u.v$)((t=>e((0,i.t)("There was an issue deleting the selected layers: %s",t)))))}},(a=>{const n=B?[{key:"delete",name:(0,i.t)("Delete"),onSelect:a,type:"danger"}]:[];return(0,x.tZ)(g.Z,{className:"annotation-layers-list-view",columns:K,count:m,data:b,fetchData:v,filters:q,initialSort:z,loading:o,pageSize:25,bulkActions:n,bulkSelectEnabled:f,disableBulkSelect:C,addDangerToast:e,addSuccessToast:t,emptyState:F,refreshData:k})})))}))},83379:(e,t,a)=>{function n(e){return e?`${e.first_name} ${e.last_name}`:""}a.d(t,{Z:()=>n})}}]);
//# sourceMappingURL=f5a03fb5cc6fcd1e4cce.chunk.js.map