import React from 'react';
import Header from '../Common/Header';
import Sidebar from './Sidebar';

const MainLayout = ({ children }) => {
  return (
    <div className="h-screen bg-slate-100 flex flex-col">
      <Header />
      <div className="flex flex-1 overflow-hidden">
        <Sidebar />
        <main className="flex-1 overflow-y-auto">
          {children}
        </main>
      </div>
    </div>
  );
};

export default MainLayout;